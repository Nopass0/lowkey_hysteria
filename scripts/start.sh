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

# Запускаем через nohup — процесс выживет после закрытия SSH
cd "$SCRIPT_DIR/.."
nohup "$BINARY" >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

echo "[start.sh] Сервер запущен (PID=$SERVER_PID)"
echo "[start.sh] Логи: $LOG_FILE"
echo "[start.sh] Для остановки: ./scripts/stop.sh"
