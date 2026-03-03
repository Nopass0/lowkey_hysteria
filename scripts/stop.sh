#!/bin/bash
# ============================================================
# scripts/stop.sh — Остановка Lowkey VPN Hysteria2 сервера
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/../logs/server.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "[stop.sh] PID файл не найден — сервер скорее всего не запущен."
    exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    echo "[stop.sh] Останавливаем сервер (PID=$PID)..."
    kill -SIGTERM "$PID"
    sleep 2
    if kill -0 "$PID" 2>/dev/null; then
        echo "[stop.sh] Принудительная остановка..."
        kill -SIGKILL "$PID"
    fi
    echo "[stop.sh] Сервер остановлен ✓"
fi

rm -f "$PID_FILE"
