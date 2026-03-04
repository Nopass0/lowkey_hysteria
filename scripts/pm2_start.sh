#!/usr/bin/env bash
# =============================================================================
#  Lowkey Hysteria2 VPN Server — PM2 Start Script
#
#  Usage:  chmod +x pm2_start.sh && sudo ./pm2_start.sh
#
#  What it does:
#    1. Checks/installs Go ≥ 1.21
#    2. Checks/installs Node.js LTS (via nvm or apt/yum)
#    3. Checks/installs PM2 globally
#    4. Opens firewall ports (7000/udp, 8080/tcp)
#    5. Enables IP forwarding + NAT for VPN subnet (172.20.0.0/24)
#    6. Builds the Go binary
#    7. Starts / restarts the server in PM2
# =============================================================================

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${CYAN}══ $* ══${NC}"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO_DIR/main"
ENV_FILE="$REPO_DIR/.env"
PM2_APP_NAME="lowkey-vpn"

# ─── 1. Check / install Go ────────────────────────────────────────────────────
GO_MIN="1.21"
step "Checking Go installation"

check_go() {
    if command -v go &>/dev/null; then
        local ver; ver=$(go version | awk '{print $3}' | sed 's/go//')
        local major minor req_major req_minor
        IFS='.' read -r major minor _ <<< "$ver"
        IFS='.' read -r req_major req_minor _ <<< "$GO_MIN"
        if (( major > req_major || (major == req_major && minor >= req_minor) )); then
            info "Go $ver is installed ✓"
            return 0
        fi
        warn "Go $ver is too old (need ≥ $GO_MIN) — updating..."
    else
        warn "Go not found — installing..."
    fi
    install_go
}

install_go() {
    local latest
    latest=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1 | sed 's/go//')
    info "Downloading Go $latest..."

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv6l)  arch="armv6l" ;;
        *)       error "Unsupported CPU: $arch" ;;
    esac

    local tarball="go${latest}.linux-${arch}.tar.gz"
    curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    export PATH="/usr/local/go/bin:$PATH"
    info "Go $(go version) installed ✓"
}

check_go
export PATH="/usr/local/go/bin:$PATH"

# ─── 2. Check / install Node.js ───────────────────────────────────────────────
step "Checking Node.js installation"

install_node() {
    info "Installing Node.js LTS via NodeSource..."
    if command -v apt-get &>/dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif command -v yum &>/dev/null; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo yum install -y nodejs
    elif command -v dnf &>/dev/null; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo dnf install -y nodejs
    else
        # Fallback: install via nvm
        warn "Could not detect package manager — installing via nvm..."
        curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
        export NVM_DIR="$HOME/.nvm"
        # shellcheck disable=SC1091
        [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
        nvm install --lts
        nvm use --lts
    fi
}

if command -v node &>/dev/null; then
    info "Node.js $(node --version) is installed ✓"
else
    install_node
fi

# ─── 3. Check / install PM2 ───────────────────────────────────────────────────
step "Checking PM2 installation"

if command -v pm2 &>/dev/null; then
    info "PM2 $(pm2 --version) is installed ✓"
else
    warn "PM2 not found — installing globally..."
    npm install -g pm2
    info "PM2 $(pm2 --version) installed ✓"
fi

# ─── 4. Set up .env ───────────────────────────────────────────────────────────
step "Setting up .env"

if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$REPO_DIR/.env.example" ]]; then
        warn ".env not found — copying from .env.example"
        cp "$REPO_DIR/.env.example" "$ENV_FILE"
    else
        warn ".env not found — using defaults (port 7000)"
    fi
else
    info "Using $ENV_FILE ✓"
fi

# ─── 5. Firewall & network setup ─────────────────────────────────────────────
step "Configuring firewall and NAT"

LISTEN_PORT=$(grep -E '^LISTEN_ADDR' "$ENV_FILE" 2>/dev/null | cut -d: -f2 | tr -d '[:space:]' || echo "7000")
HTTP_PORT=$(grep -E '^HTTP_ADDR' "$ENV_FILE" 2>/dev/null | cut -d: -f2 | tr -d '[:space:]' || echo "8080")

if command -v ufw &>/dev/null; then
    info "Opening ports in ufw..."
    sudo ufw allow "${LISTEN_PORT}/udp" &>/dev/null || true
    sudo ufw allow "${HTTP_PORT}/tcp" &>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    info "Opening ports in firewalld..."
    sudo firewall-cmd --permanent --add-port="${LISTEN_PORT}/udp" &>/dev/null || true
    sudo firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" &>/dev/null || true
    sudo firewall-cmd --reload &>/dev/null || true
fi

# Also open with iptables directly (works even without ufw/firewalld)
sudo iptables -I INPUT -p udp --dport "${LISTEN_PORT}" -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport "${HTTP_PORT}" -j ACCEPT 2>/dev/null || true

info "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1 || true

info "Setting up NAT masquerade and MSS clamping for VPN subnet 10.42.0.0/16..."
# Remove stale rules
sudo iptables -t nat -D POSTROUTING -s 10.42.0.0/16 ! -d 10.42.0.0/16 -j MASQUERADE 2>/dev/null || true
sudo iptables -D FORWARD -s 10.42.0.0/16 -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -d 10.42.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
sudo iptables -t mangle -D FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# Add fresh rules
sudo iptables -t nat -A POSTROUTING -s 10.42.0.0/16 ! -d 10.42.0.0/16 -j MASQUERADE
sudo iptables -A FORWARD -s 10.42.0.0/16 -j ACCEPT
sudo iptables -A FORWARD -d 10.42.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT

# MSS Clamping is critical for UDP tunnels to prevent packet fragmentation issues
sudo iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
info "NAT and MSS rules applied ✓"

# ─── 6. Build Go binary ───────────────────────────────────────────────────────
step "Building Go binary"

cd "$REPO_DIR"
info "Running: go build -o main ."
go build -o "$BINARY" .
info "Build complete → $BINARY ✓"

# ─── 7. Start / restart in PM2 ───────────────────────────────────────────────
step "Starting server in PM2"

if pm2 list | grep -q "$PM2_APP_NAME"; then
    info "Restarting existing PM2 process '$PM2_APP_NAME'..."
    pm2 restart "$PM2_APP_NAME" --update-env
else
    info "Starting '$PM2_APP_NAME' in PM2..."
    pm2 start "$BINARY" \
        --name "$PM2_APP_NAME" \
        --interpreter none \
        --no-autorestart \
        --log "$REPO_DIR/logs/vpn.log" \
        --error "$REPO_DIR/logs/vpn-error.log" \
        --env production
fi

pm2 save
info "PM2 process saved ✓"

# ─── 8. Status & autostart hint ──────────────────────────────────────────────
echo ""
pm2 list
echo ""
info "Server '$PM2_APP_NAME' is running ✓"
info "Ports: QUIC/UDP :${LISTEN_PORT}  ·  HTTP API :${HTTP_PORT}"
echo ""
warn "To enable autostart on system reboot, run:"
echo "    pm2 startup"
echo "    (copy and run the generated command as root)"
