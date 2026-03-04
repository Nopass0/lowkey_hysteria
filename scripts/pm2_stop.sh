#!/usr/bin/env bash
# =============================================================================
#  Lowkey Hysteria2 VPN Server — PM2 Stop Script
#
#  Usage:  chmod +x pm2_stop.sh && ./pm2_stop.sh [--clean-iptables]
#
#  Flags:
#    --clean-iptables   Also remove NAT/FORWARD iptables rules for VPN subnet
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

PM2_APP_NAME="lowkey-vpn"
CLEAN_IPTABLES=false

# Parse args
for arg in "$@"; do
    case "$arg" in
        --clean-iptables) CLEAN_IPTABLES=true ;;
        *) warn "Unknown argument: $arg" ;;
    esac
done

# ─── 1. Check PM2 ─────────────────────────────────────────────────────────────
if ! command -v pm2 &>/dev/null; then
    warn "PM2 is not installed — nothing to stop"
    exit 0
fi

# ─── 2. Stop & delete from PM2 ────────────────────────────────────────────────
if pm2 list | grep -q "$PM2_APP_NAME"; then
    info "Stopping PM2 process '$PM2_APP_NAME'..."
    pm2 stop "$PM2_APP_NAME" 2>/dev/null || true
    
    info "Deleting '$PM2_APP_NAME' from PM2 process list..."
    pm2 delete "$PM2_APP_NAME" 2>/dev/null || true
    
    pm2 save
    info "PM2 process stopped and removed ✓"
else
    warn "PM2 process '$PM2_APP_NAME' is not running"
fi

# ─── 3. Optional: clean iptables ──────────────────────────────────────────────
if [[ "$CLEAN_IPTABLES" == "true" ]]; then
    echo ""
    info "Cleaning VPN iptables rules..."
    sudo iptables -t nat -D POSTROUTING -s 172.20.0.0/24 ! -d 172.20.0.0/24 -j MASQUERADE 2>/dev/null && info "Removed MASQUERADE rule" || warn "MASQUERADE rule not found"
    sudo iptables -D FORWARD -s 172.20.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && info "Removed FORWARD ESTABLISHED rule" || true
    sudo iptables -D FORWARD -d 172.20.0.0/24 -j ACCEPT 2>/dev/null && info "Removed FORWARD rule" || true
    info "iptables cleaned ✓"
else
    warn "NAT/iptables rules were NOT removed (pass --clean-iptables to remove them)"
fi

echo ""
info "Done. To check status: pm2 list"
