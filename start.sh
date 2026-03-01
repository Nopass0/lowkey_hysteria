#!/usr/bin/env bash
# =============================================================================
#  Lowkey Hysteria2 VPN Server — startup script
#  Usage:  chmod +x start.sh && ./start.sh
# =============================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$REPO_DIR/hysteria_server"
ENV_FILE="$REPO_DIR/.env"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── 1. Check / install Go ────────────────────────────────────────────────────
GO_MIN="1.21"   # minimum required version

check_go() {
    if command -v go &>/dev/null; then
        local ver
        ver=$(go version | awk '{print $3}' | sed 's/go//')
        info "Go $ver already installed."
        # Compare major.minor
        local major minor req_major req_minor
        IFS='.' read -r major minor _ <<< "$ver"
        IFS='.' read -r req_major req_minor _ <<< "$GO_MIN"
        if (( major > req_major || (major == req_major && minor >= req_minor) )); then
            return 0
        fi
        warn "Go $ver is older than required $GO_MIN — installing latest..."
    else
        warn "Go is NOT installed — installing..."
    fi
    install_go
}

install_go() {
    # Fetch the latest stable Go version number
    local latest
    latest=$(curl -fsSL https://go.dev/VERSION?m=text | head -1 | sed 's/go//')
    info "Installing Go $latest ..."

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv6l)  arch="armv6l" ;;
        *)        error "Unsupported architecture: $arch" ;;
    esac

    local tarball="go${latest}.linux-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    curl -fsSL "$url" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm "/tmp/${tarball}"

    # Make sure PATH is updated for this session
    export PATH="/usr/local/go/bin:$PATH"
    info "Go $(go version) installed successfully."
}

check_go

# ─── 2. Set up .env ───────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$REPO_DIR/.env.example" ]]; then
        warn ".env not found — copying from .env.example. Please edit it before using!"
        cp "$REPO_DIR/.env.example" "$ENV_FILE"
    else
        warn ".env not found. Running with defaults (localhost backend, port 7000)."
    fi
else
    info "Using $ENV_FILE"
fi

# ─── 3. Build ─────────────────────────────────────────────────────────────────
info "Building hysteria_server..."
cd "$REPO_DIR"
export PATH="/usr/local/go/bin:$PATH"
go build -o "$BINARY" .
info "Build complete → $BINARY"

# ─── 4. Open firewall port (optional, needs sudo) ─────────────────────────────
LISTEN_PORT=$(grep -E '^LISTEN_ADDR' "$ENV_FILE" 2>/dev/null | cut -d: -f2 | tr -d '[:space:]' || echo "7000")
if command -v ufw &>/dev/null; then
    info "Opening UDP port ${LISTEN_PORT} in ufw..."
    sudo ufw allow "${LISTEN_PORT}/udp" &>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    info "Opening UDP port ${LISTEN_PORT} in firewalld..."
    sudo firewall-cmd --permanent --add-port="${LISTEN_PORT}/udp" &>/dev/null || true
    sudo firewall-cmd --reload &>/dev/null || true
fi

# ─── 5. Run ───────────────────────────────────────────────────────────────────
info "Starting Hysteria2 VPN server on :${LISTEN_PORT} ..."
echo ""
exec "$BINARY"
