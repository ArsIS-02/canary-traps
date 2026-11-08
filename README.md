# Canary — сетевые ловушки для домашней лаборатории

Слушает «сладкие» порты (SMB 445, MSSQL 1433, MySQL 3306, VNC 5900, Telnet 2323,
HTTP 8081, Redis 6379, Memcached 11211, Docker API 2375). Любое касание — событие в Graylog
по GELF (UDP) и строка в JSONL-журнал. Попытки логина (Telnet, HTTP Basic)
разбираются и уходят событием `auth` с логином и паролем.

Ложных срабатываний быть не должно: легитимным сервисам эти порты на хосте
не нужны. Любое касание — сканирование или lateral movement.

## Сборка и запуск (rootless podman)

```bash
podman build -t localhost/canary:latest .
mkdir -p ~/canary/data
podman run -d --name canary \
  -p 445:445 -p 1433:1433 -p 3306:3306 -p 5900:5900 -p 2323:2323 \
  -p 8081:8081 -p 6379:6379 -p 11211:11211 -p 2375:2375 \
  -v ~/canary/data:/data:Z \
  -e GELF_HOST=host.containers.internal -e GELF_PORT=12206 \
  localhost/canary:latest
```

Порты ≥ 80 в rootless работают (`net.ipv4.ip_unprivileged_port_start=80`).
Набор портов меняется переменной `CANARY_PORTS` (например `"445:smb,8081:http"`).

## Автозапуск (systemd user, quadlet)

```bash
mkdir -p ~/.config/containers/systemd
cp container/canary.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start canary
```

## Проверка

```bash
nc -zv <хост> 445
curl -u admin:password http://<хост>:8081/
printf 'admin\npassword\n' | nc <хост> 2323
```

События: Graylog, вход «Homelab tools» (GELF UDP 12206), запрос `tool:canary`.
Поля: `event` (connect/auth/startup), `src_ip`, `src_port`, `dst_port`,
`proto`, `payload`, `username`, `password`, `http_request`, `http_host`.

Локальный журнал: `~/canary/data/canary.jsonl`.
