"""Локальные тесты canary: поднимаем сервер на высоких портах, ловим GELF и JSONL."""
import asyncio
import base64
import json
import os
import socket
import sys
import threading
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run_server(tmp_path, gelf_port, ready):
    os.environ["CANARY_PORTS"] = "18081:http,12323:telnet"
    os.environ["GELF_HOST"] = "127.0.0.1"
    os.environ["GELF_PORT"] = str(gelf_port)
    os.environ["LOG_DIR"] = str(tmp_path)
    import canary
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    ready.set()
    try:
        loop.run_until_complete(canary.main())
    except KeyboardInterrupt:
        pass


def udp_sink(port, got, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.3)
    while not stop.is_set():
        try:
            data, _ = s.recvfrom(65535)
            got.append(json.loads(zlib.decompress(data)))
        except socket.timeout:
            continue
    s.close()


def test_connect_and_auth(tmp_path):
    gelf_port = 19099
    ready, stop = threading.Event(), threading.Event()
    got = []
    sink = threading.Thread(target=udp_sink, args=(gelf_port, got, stop), daemon=True)
    sink.start()
    srv = threading.Thread(target=run_server, args=(tmp_path, gelf_port, ready), daemon=True)
    srv.start()
    ready.wait(5)
    import time
    time.sleep(0.8)   # серверы поднялись

    # 1) HTTP с Basic-логином
    auth = base64.b64encode(b"admin:qwerty").decode()
    s = socket.create_connection(("127.0.0.1", 18081), timeout=5)
    s.sendall(f"GET /index.html HTTP/1.1\r\nHost: nas.local\r\nAuthorization: Basic {auth}\r\n\r\n".encode())
    assert b"401" in s.recv(4096)
    s.close()

    # 2) Telnet login/password
    t = socket.create_connection(("127.0.0.1", 12323), timeout=5)
    t.recv(1024)
    t.sendall(b"root\n")
    t.recv(1024)
    t.sendall(b"toor\n")
    t.close()

    time.sleep(1.0)
    stop.set()
    sink.join(2)

    msgs = [g for g in got if g.get("_tool") == "canary"]
    kinds = {(m.get("_event"), m.get("_proto")) for m in msgs}
    assert ("auth", "http") in kinds and ("auth", "telnet") in kinds, kinds
    http = next(m for m in msgs if m.get("_proto") == "http" and m.get("_event") == "auth")
    assert http["_username"] == "admin" and http["_password"] == "qwerty"
    tel = next(m for m in msgs if m.get("_proto") == "telnet")
    assert tel["_username"] == "root" and tel["_password"] == "toor"

    lines = (tmp_path / "canary.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 2
