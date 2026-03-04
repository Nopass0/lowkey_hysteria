#!/bin/bash
# ============================================================
# scripts/start.sh — Запуск Lowkey VPN Hysteria2 сервера
# ============================================================
#
# Запускает сервер через nohup, поэтому процесс продолжает
# работать даже после закрытия SSH сессии.
#
# Использование:
#   chmod +x scripts/start.sh
#   ./scripts/start.sh
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/../hysteria_server"
LOG_FILE="$SCRIPT_DIR/../logs/server.log"
PID_FILE="$SCRIPT_DIR/../logs/server.pid"

# Создаём директорию для логов
mkdir -p "$(dirname "$LOG_FILE")"

# Проверяем, не запущен ли уже сервер
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[start.sh] Сервер уже запущен (PID=$PID). Остановите его сначала через stop.sh"
        exit 1
    fi
fi

# Собираем, если нет бинарника
if [ ! -f "$BINARY" ]; then
    echo "[start.sh] Бинарник не найден. Собираем..."
    cd "$SCRIPT_DIR/.."
    go build -o hysteria_server .
    echo "[start.sh] Сборка завершена ✓"
fi

# Включаем форвардинг и NAT
echo "[start.sh] Настройка NAT и MSS Clamping для 10.42.0.0/16..."
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
sudo iptables -t nat -A POSTROUTING -s 10.42.0.0/16 ! -d 10.42.0.0/16 -j MASQUERADE || true
sudo iptables -A FORWARD -s 10.42.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT || true
sudo iptables -A FORWARD -d 10.42.0.0/16 -j ACCEPT || true
sudo iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true

# Запускаем через nohup — процесс выживет после закрытия SSH
cd "$SCRIPT_DIR/.."
nohup "$BINARY" >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

echo "[start.sh] Сервер запущен (PID=$SERVER_PID)"
echo "[start.sh] Логи: $LOG_FILE"
echo "[start.sh] Для остановки: ./scripts/stop.sh"
