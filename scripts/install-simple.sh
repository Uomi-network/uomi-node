#!/usr/bin/env bash
# scripts/install-node.sh — hardened & idempotent installer for Uomi node
set -Eeuo pipefail
trap 'echo "[ERROR] Command failed at line $LINENO"; exit 1' ERR

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
require curl; require jq; require tar; require uname

# ---- Config (override via env) ----
UOMI_NAME="${UOMI_NAME:-uomi-node}"
UOMI_CHAIN="${UOMI_CHAIN:-dev}"              # sesuaikan nama chain resmi jika perlu
UOMI_BASE="${UOMI_BASE_PATH:-/var/lib/uomi}"
UOMI_USER="${UOMI_USER:-uomi}"
BIN_DIR="/usr/local/bin"
SERVICE="/etc/systemd/system/uomi.service"

detect_os() {
  . /etc/os-release || true
  case "${ID_LIKE:-} ${ID:-}" in
    *debian*|*ubuntu*) PKG=apt ;;
    *fedora*|*rhel*|*centos*) PKG=dnf ;;
    *) echo "Unsupported distro"; exit 1 ;;
  esac
}

install_deps() {
  if [ "$PKG" = apt ]; then
    sudo apt-get update -y
    sudo apt-get install -y build-essential clang pkg-config libssl-dev git curl jq
  else
    sudo dnf install -y clang pkg-config openssl-devel git curl jq make gcc
  fi
}

ensure_user() {
  if ! id -u "$UOMI_USER" >/dev/null 2>&1; then
    sudo useradd -r -m -d "$UOMI_BASE" -s /usr/sbin/nologin "$UOMI_USER"
  fi
  sudo mkdir -p "$UOMI_BASE" && sudo chown -R "$UOMI_USER:$UOMI_USER" "$UOMI_BASE"
}

install_rust() {
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  rustup target add wasm32-unknown-unknown || true
}

fetch_ipfs_clients() {
  # Selaras README: simpan bin di ./client/ipfs-manager/src/
  mkdir -p ./client/ipfs-manager/src/
  curl -fsSL https://storage.uomi.ai/ipfs_linux_amd64 -o ./client/ipfs-manager/src/ipfs_linux_amd64
  curl -fsSL https://storage.uomi.ai/ipfs_linux_arm64 -o ./client/ipfs-manager/src/ipfs_linux_arm64
  curl -fsSL https://storage.uomi.ai/ipfs_macOS      -o ./client/ipfs-manager/src/ipfs_macOS
  chmod +x ./client/ipfs-manager/src/ipfs_*
}

build_node() {
  # jika repo belum ada (installer dijalankan di luar repo), clone dulu
  if [ ! -f Cargo.toml ]; then
    git clone --recurse-submodules https://github.com/Uomi-network/uomi-node.git
    cd uomi-node
  fi
  fetch_ipfs_clients
  cargo build --release
  sudo install -m 0755 ./target/release/uomi "$BIN_DIR/uomi"
}

setup_systemd() {
  sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Uomi Node
Wants=network-online.target
After=network-online.target

[Service]
User=${UOMI_USER}
Group=${UOMI_USER}
ExecStart=${BIN_DIR}/uomi --base-path ${UOMI_BASE} --chain ${UOMI_CHAIN} --name ${UOMI_NAME} --port 30333 --rpc-port 9944 --validator
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now uomi
  echo "Done. Follow logs with: sudo journalctl -u uomi -f"
}

main() {
  detect_os
  install_deps
  ensure_user
  install_rust
  build_node
  setup_systemd
}
main "$@"
