#!/bin/bash
# ============================================================
# scripts/install-service.sh — Установка как systemd сервис
# ============================================================
#
# Создаёт /etc/systemd/system/lowkey-vpn.service и включает
# автозапуск. После установки сервер стартует при перезагрузке
# VPS автоматически.
#
# Использование (от root):
#   chmod +x scripts/install-service.sh
#   sudo ./scripts/install-service.sh
# ============================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[install] Требуются права root. Запустите: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(realpath "$SCRIPT_DIR/..")"
BINARY="$APP_DIR/hysteria_server"

# Собираем бинарник если ещё нет
if [ ! -f "$BINARY" ]; then
    echo "[install] Компилируем..."
    cd "$APP_DIR"
    go build -o hysteria_server .
fi

# Создаём systemd unit-файл
cat > /etc/systemd/system/lowkey-vpn.service << EOF
[Unit]
Description=Lowkey VPN Hysteria2 Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$BINARY
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lowkey-vpn

# Разрешаем управление сетью
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Настройка переменных окружения — используем .env файл
EnvironmentFile=-$APP_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lowkey-vpn
systemctl start lowkey-vpn

echo ""
echo "=========================================="
echo " Lowkey VPN установлен как systemd сервис"
echo "=========================================="
echo " Статус:      systemctl status lowkey-vpn"
echo " Логи:        journalctl -u lowkey-vpn -f"
echo " Перезапуск:  systemctl restart lowkey-vpn"
echo " Остановка:   systemctl stop lowkey-vpn"
echo "=========================================="
