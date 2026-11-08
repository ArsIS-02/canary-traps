#!/usr/bin/env python3
"""Canary — сетевые ловушки для домашней лаборатории.

Слушает набор «сладких» портов (SMB, RDP, MSSQL, VNC, Telnet, HTTP, Redis,
Memcached). Любое касание — событие в Graylog по GELF (UDP) и строка
в JSONL-журнал. Попытки аутентификации (Telnet login/password, HTTP Basic)
разбираются и уходят отдельным событием с логином и паролем.

Настройка — переменными окружения:
  CANARY_PORTS  "445:smb,3389:rdp,..." (порт:протокол через запятую)
  GELF_HOST     куда слать события (host.containers.internal из контейнера)
  GELF_PORT     вход GELF UDP Graylog (по умолчанию 12206)
  LOG_DIR       каталог JSONL-журнала (по умолчанию /data)
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import socket
import struct
import time
import zlib

log = logging.getLogger("canary")

DEFAULT_PORTS = "445:smb,1433:mssql,3306:mysql,5900:vnc,2323:telnet,8081:http,6379:redis,11211:memcached,2375:docker"
READ_BYTES = 1024
READ_TIMEOUT = 4.0

GELF_HOST = os.environ.get("GELF_HOST", "host.containers.internal")
GELF_PORT = int(os.environ.get("GELF_PORT", "12206"))
LOG_DIR = os.environ.get("LOG_DIR", "/data")
HOSTNAME = socket.gethostname()

# ------------------------------------------------------------ GELF (UDP, zlib — как принимает Graylog)
_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def gelf(event: str, message: str, level: int = 4, **fields) -> None:
    msg = {"version": "1.1", "host": HOSTNAME, "short_message": message[:250],
           "level": level, "_tool": "canary", "_homelab_app": "canary", "_event": event}
    for k, v in fields.items():
        if v is not None and v != "":
            msg[f"_{k}"] = str(v)[:300]
    try:
        _udp.sendto(zlib.compress(json.dumps(msg, ensure_ascii=False).encode()), (GELF_HOST, GELF_PORT))
    except OSError as e:
        log.warning("gelf: %s", e)


def journal(rec: dict) -> None:
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "canary.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("journal: %s", e)


# ------------------------------------------------------------ разбор протоколов
def printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def parse_http(data: bytes) -> dict:
    """Request-line, Host и Basic-логин из первого запроса."""
    out = {}
    try:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except ValueError:
        return out
    lines = head.split("\r\n")
    out["http_request"] = lines[0][:200]
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "host":
            out["http_host"] = v[:100]
        elif k == "authorization" and v.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(v[6:]).decode("utf-8", "replace").partition(":")
                out["username"], out["password"] = user[:64], pw[:64]
            except Exception:  # noqa: BLE001
                pass
    return out


HTTP_REPLY = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nas\"\r\n"
              b"Content-Type: text/html\r\nContent-Length: 44\r\nConnection: close\r\n\r\n"
              b"<html><body><h1>401 Unauthorized</h1></body></html>")

BANNERS = {
    "telnet": b"\r\nDebian GNU/Linux 11\r\nnas login: ",
    "ftp": b"220 (vsFTPd 3.0.3)\r\n",
    "redis": b"-NOAUTH Authentication required.\r\n",
    "vnc": b"RFB 003.008\n",
    "mysql": None,   # бинарный handshake не имитируем — просто молчим
}


async def telnet_auth(reader, writer, rec) -> None:
    """Диалог login/password: два ввода пользователя -> событие auth."""
    try:
        writer.write(BANNERS["telnet"])
        await writer.drain()
        user = (await asyncio.wait_for(reader.readline(), 10)).decode("utf-8", "replace").strip()[:64]
        writer.write(b"Password: ")
        await writer.drain()
        pw = (await asyncio.wait_for(reader.readline(), 10)).decode("utf-8", "replace").strip()[:64]
        writer.write(b"Login incorrect\r\nnas login: ")
        await writer.drain()
        if user or pw:
            rec.update(username=user, password=pw)
    except (asyncio.TimeoutError, ConnectionError):
        pass


async def read_payload(reader, proto: str) -> bytes:
    """Читать до READ_BYTES: первый кусок ждём READ_TIMEOUT, дальше — пауза 1.5 с;
    для HTTP хватает конца заголовков. При таймауте накопленное не теряется."""
    data = b""
    try:
        while len(data) < READ_BYTES:
            chunk = await asyncio.wait_for(reader.read(READ_BYTES - len(data)),
                                           READ_TIMEOUT if not data else 1.5)
            if not chunk:
                break
            data += chunk
            if proto == "http" and b"\r\n\r\n" in data:
                break
    except asyncio.TimeoutError:
        pass
    return data


async def handle(reader, writer, port: int, proto: str) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    src_ip, src_port = peer[0], peer[1]
    rec = {"ts": time.time(), "src_ip": src_ip, "src_port": src_port, "dst_port": port, "proto": proto}

    if proto == "telnet":
        await telnet_auth(reader, writer, rec)     # баннер и диалог сразу
        data = b""
    else:
        banner = BANNERS.get(proto)
        if banner:                                  # redis/vnc/ftp: баннер сразу
            writer.write(banner)
            try:
                await writer.drain()
            except ConnectionError:
                pass
        data = await read_payload(reader, proto)

    if data:
        rec["payload"] = printable(data)[:200]
        rec["payload_hex"] = data[:64].hex()
    if proto == "http" and data:
        rec.update(parse_http(data))
        writer.write(HTTP_REPLY)
        try:
            await writer.drain()
        except ConnectionError:
            pass
    writer.close()

    has_creds = bool(rec.get("username") or rec.get("password"))
    event = "auth" if has_creds else "connect"
    level = 3 if has_creds else 4          # 3=error? нет: syslog 3=Error, 4=Warning — auth заметнее
    message = f"canary: {proto}/{port} касание с {src_ip}:{src_port}"
    if has_creds:
        message = f"canary: {proto}/{port} логин {rec.get('username', '')!r} с {src_ip}"
    journal(dict(rec, event=event))
    gelf(event, message, level, **rec)
    log.info("%s -> %s", src_ip, message)


async def main() -> None:
    ports = []
    for item in os.environ.get("CANARY_PORTS", DEFAULT_PORTS).split(","):
        p, _, proto = item.strip().partition(":")
        if p.isdigit():
            ports.append((int(p), proto or "tcp"))
    servers = []
    for port, proto in ports:
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port, t=proto: handle(r, w, p, t), "0.0.0.0", port)
            servers.append(srv)
            log.info("слушаю %s/%s", proto, port)
        except OSError as e:
            log.error("порт %s (%s): %s", port, proto, e)
    if not servers:
        raise SystemExit("не удалось открыть ни одного порта")
    gelf("startup", f"canary: запущен, портов: {len(servers)}", 5, ports=",".join(str(p) for p, _ in ports))
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(main())
