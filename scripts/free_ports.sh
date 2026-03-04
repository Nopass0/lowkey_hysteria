#!/bin/bash
# ============================================================
# scripts/free_ports.sh — Очистка занятых портов
# ============================================================
#
# Находит и убивает любые процессы, которые занимают порты
# 7000 (UDP - Hysteria) и 8080 (TCP - API).
#
# Использование:
#   chmod +x scripts/free_ports.sh
#   sudo ./scripts/free_ports.sh
# ============================================================

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PORTS_UDP=(7000)
PORTS_TCP=(8080)

echo -e "${YELLOW}[INFO] Начало очистки портов...${NC}"

# Очистка UDP портов
for port in "${PORTS_UDP[@]}"; do
    PID=$(lsof -t -i udp:"$port" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        echo -e "${RED}[KILL] Нашел процесс на UDP:$port (PID=$PID). Убиваю...${NC}"
        kill -9 $PID 2>/dev/null || true
    else
        echo -e "${GREEN}[OK] UDP:$port свободен${NC}"
    fi
done

# Очистка TCP портов
for port in "${PORTS_TCP[@]}"; do
    PID=$(lsof -t -i tcp:"$port" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        echo -e "${RED}[KILL] Нашел процесс на TCP:$port (PID=$PID). Убиваю...${NC}"
        kill -9 $PID 2>/dev/null || true
    else
        echo -e "${GREEN}[OK] TCP:$port свободен${NC}"
    fi
done

# Также проверим PM2 если он есть
if command -v pm2 &>/dev/null; then
    if pm2 list | grep -q "lowkey-vpn"; then
        echo -e "${YELLOW}[PM2] Останавливаю lowkey-vpn в PM2...${NC}"
        pm2 stop lowkey-vpn 2>/dev/null || true
    fi
fi

echo -e "${GREEN}[DONE] Порты очищены. Теперь можете запускать сервер!${NC}"
