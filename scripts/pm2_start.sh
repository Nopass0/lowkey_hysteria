#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${CYAN}== $* ==${NC}"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO_DIR/hysteria_server"
ENV_FILE="$REPO_DIR/.env"
PM2_APP_NAME="${PM2_APP_NAME:-lowkey-vpn}"
PM2_MTPROTO_NAME="${PM2_APP_NAME}-mtproto"
GO_MIN="1.21"

step "Checking Go installation"

install_go() {
    local latest arch tarball
    latest=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1 | sed 's/go//')
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv6l) arch="armv6l" ;;
        *) error "Unsupported CPU architecture: $arch" ;;
    esac

    tarball="go${latest}.linux-${arch}.tar.gz"
    info "Installing Go ${latest}..."
    curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
    sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

if command -v go >/dev/null 2>&1; then
    GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    IFS='.' read -r GO_MAJOR GO_MINOR _ <<< "$GO_VER"
    IFS='.' read -r MIN_MAJOR MIN_MINOR _ <<< "$GO_MIN"
    if (( GO_MAJOR > MIN_MAJOR || (GO_MAJOR == MIN_MAJOR && GO_MINOR >= MIN_MINOR) )); then
        info "Go ${GO_VER} is installed"
    else
        warn "Go ${GO_VER} is too old, upgrading"
        install_go
    fi
else
    warn "Go not found, installing"
    install_go
fi

export PATH="/usr/local/go/bin:$PATH"

step "Checking Node.js installation"

install_node() {
    if command -v apt-get >/dev/null 2>&1; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
        return
    fi
    if command -v yum >/dev/null 2>&1; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo yum install -y nodejs
        return
    fi
    if command -v dnf >/dev/null 2>&1; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo dnf install -y nodejs
        return
    fi
    error "Could not install Node.js automatically"
}

if command -v node >/dev/null 2>&1; then
    info "Node.js $(node --version) is installed"
else
    warn "Node.js not found, installing"
    install_node
fi

step "Checking Xray installation"

install_xray() {
    local arch zipball url
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        armv6l) arch="arm32-v6a" ;;
        *) error "Unsupported CPU architecture for Xray: $arch" ;;
    esac

    zipball="Xray-linux-${arch}.zip"
    url="https://github.com/XTLS/Xray-core/releases/latest/download/${zipball}"

    info "Installing latest Xray-core..."
    curl -fsSL -L "$url" -o "/tmp/${zipball}"
    if ! command -v unzip >/dev/null 2>&1; then
        sudo apt-get update -y && sudo apt-get install -y unzip
    fi
    sudo unzip -o "/tmp/${zipball}" xray -d /usr/local/bin/
    sudo chmod +x /usr/local/bin/xray
    rm -f "/tmp/${zipball}"
}

if command -v xray >/dev/null 2>&1; then
    info "Xray $(xray -version | head -n1) is installed"
else
    warn "Xray not found, installing"
    install_xray
fi

step "Checking PM2 installation"

if command -v pm2 >/dev/null 2>&1; then
    info "PM2 $(pm2 --version) is installed"
else
    warn "PM2 not found, installing"
    npm install -g pm2
fi

step "Preparing .env"

if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$REPO_DIR/.env.example" ]]; then
        cp "$REPO_DIR/.env.example" "$ENV_FILE"
        warn ".env was missing, copied from .env.example"
    else
        error ".env is missing and .env.example was not found"
    fi
else
    info "Using $ENV_FILE"
fi

LISTEN_PORT=$(grep -E '^LISTEN_ADDR' "$ENV_FILE" 2>/dev/null | cut -d: -f2 | tr -d '[:space:]' || echo "7000")
HTTP_PORT=$(grep -E '^HTTP_ADDR' "$ENV_FILE" 2>/dev/null | cut -d: -f2 | tr -d '[:space:]' || echo "8080")
XRAY_PORT=$(grep -E '^XRAY_PORT' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo "443")
MTPROTO_ENABLED=$(grep -E '^MTPROTO_ENABLED=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "false")
MTPROTO_PORT=$(grep -E '^MTPROTO_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo "8443")

if [[ "$MTPROTO_ENABLED" == "true" ]]; then
    if [[ "$MTPROTO_PORT" == "$XRAY_PORT" || "$MTPROTO_PORT" == "$HTTP_PORT" ]]; then
        error "MTProto port ${MTPROTO_PORT} conflicts with XRAY_PORT=${XRAY_PORT} or HTTP_PORT=${HTTP_PORT}"
    fi
fi

step "Configuring firewall and NAT"

if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow "${LISTEN_PORT}/udp" >/dev/null 2>&1 || true
    sudo ufw allow "${XRAY_PORT}/tcp" >/dev/null 2>&1 || true
    sudo ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
    if [[ "$MTPROTO_ENABLED" == "true" ]]; then
        sudo ufw allow "${MTPROTO_PORT}/tcp" >/dev/null 2>&1 || true
    fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port="${LISTEN_PORT}/udp" >/dev/null 2>&1 || true
    sudo firewall-cmd --permanent --add-port="${XRAY_PORT}/tcp" >/dev/null 2>&1 || true
    sudo firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
    if [[ "$MTPROTO_ENABLED" == "true" ]]; then
        sudo firewall-cmd --permanent --add-port="${MTPROTO_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    sudo firewall-cmd --reload >/dev/null 2>&1 || true
fi

sudo iptables -I INPUT -p udp --dport "${LISTEN_PORT}" -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport "${XRAY_PORT}" -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT -p tcp --dport "${HTTP_PORT}" -j ACCEPT 2>/dev/null || true
if [[ "$MTPROTO_ENABLED" == "true" ]]; then
    sudo iptables -I INPUT -p tcp --dport "${MTPROTO_PORT}" -j ACCEPT 2>/dev/null || true
fi

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1 || true

sudo iptables -t nat -D POSTROUTING -s 10.42.0.0/16 ! -d 10.42.0.0/16 -j MASQUERADE 2>/dev/null || true
sudo iptables -D FORWARD -s 10.42.0.0/16 -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -d 10.42.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
sudo iptables -t mangle -D FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

sudo iptables -t nat -A POSTROUTING -s 10.42.0.0/16 ! -d 10.42.0.0/16 -j MASQUERADE
sudo iptables -A FORWARD -s 10.42.0.0/16 -j ACCEPT
sudo iptables -A FORWARD -d 10.42.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

step "Building Go binary"

cd "$REPO_DIR"
mkdir -p "$REPO_DIR/logs"
go build -o "$BINARY" .
info "Go binary built at $BINARY"

if [[ "$MTPROTO_ENABLED" == "true" ]]; then
    step "Installing MTProto dependencies"
    if [[ -f "$REPO_DIR/package-lock.json" ]]; then
        npm ci --omit=dev
    else
        npm install --omit=dev
    fi
fi

step "Starting services in PM2"

if pm2 show "$PM2_APP_NAME" >/dev/null 2>&1; then
    pm2 restart "$PM2_APP_NAME" --update-env || \
        pm2 start "$BINARY" --name "$PM2_APP_NAME" --interpreter none --cwd "$REPO_DIR" --update-env
else
    pm2 start "$BINARY" \
        --name "$PM2_APP_NAME" \
        --interpreter none \
        --cwd "$REPO_DIR" \
        --log "$REPO_DIR/logs/vpn.log" \
        --error "$REPO_DIR/logs/vpn-error.log" \
        --env production
fi

if [[ "$MTPROTO_ENABLED" == "true" ]]; then
    if pm2 show "$PM2_MTPROTO_NAME" >/dev/null 2>&1; then
        pm2 restart "$PM2_MTPROTO_NAME" --update-env || \
            pm2 start "$REPO_DIR/scripts/mtproto_proxy.cjs" --name "$PM2_MTPROTO_NAME" --cwd "$REPO_DIR"
    else
        pm2 start "$REPO_DIR/scripts/mtproto_proxy.cjs" \
            --name "$PM2_MTPROTO_NAME" \
            --cwd "$REPO_DIR" \
            --log "$REPO_DIR/logs/mtproto.log" \
            --error "$REPO_DIR/logs/mtproto-error.log"
    fi
else
    if pm2 show "$PM2_MTPROTO_NAME" >/dev/null 2>&1; then
        pm2 delete "$PM2_MTPROTO_NAME" || true
    fi
fi

pm2 save

echo ""
pm2 list
echo ""
info "Main app: ${PM2_APP_NAME}"
info "Ports: Hysteria UDP ${LISTEN_PORT}, VLESS TCP ${XRAY_PORT}, HTTP API ${HTTP_PORT}"
if [[ "$MTPROTO_ENABLED" == "true" ]]; then
    info "MTProto: TCP ${MTPROTO_PORT}"
fi
echo ""
warn "To enable autostart on reboot, run: pm2 startup"
