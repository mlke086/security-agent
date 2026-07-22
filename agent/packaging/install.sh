#!/bin/bash
# Security Agent - Linux installer (systemd)
# Usage: curl -fsSL http://console:8000/api/v1/agents/install?token=TOKEN | bash
set -e
TOKEN="${1:-}"
CONSOLE="${2:-http://192.168.80.101:8000}"
if [ -z "$TOKEN" ]; then
  echo "Usage: $0 <enroll_token> [console_url]"
  exit 1
fi

echo "[secagent] Installing security agent..."
INSTALL_DIR="/opt/secagent"
CONFIG_DIR="/etc/secagent"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# Detect OS and arch
ARCH=$(uname -m)
case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm" ;;
  *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
OS="linux"

# Download CA certificate
echo "[secagent] Downloading CA certificate..."
curl -fsSL "$CONSOLE/api/v1/agents/ca?token=$TOKEN" -o "$CONFIG_DIR/ca.pem" || echo "[secagent] Warning: no CA cert"

# Download agent binary
echo "[secagent] Downloading agent binary for $OS/$ARCH..."
curl -fsSL "$CONSOLE/api/v1/agents/binary/$OS/$ARCH?token=$TOKEN" -o "$INSTALL_DIR/agent"
chmod +x "$INSTALL_DIR/agent"

# Write agent config
cat > "$CONFIG_DIR/config.json" << EOFCFG
{
  "console_url": "$CONSOLE",
  "ca_path": "$CONFIG_DIR/ca.pem",
  "enroll_token": "$TOKEN",
  "heartbeat_sec": 60,
  "resource_limit": {"cpu_percent": 30, "mem_percent": 30}
}
EOFCFG
# P0 (2026-07-18): Install the nuclei CLI alongside the agent so the
# "nuclei" scan engine can run. The agent itself falls back to its own
# matcher when nuclei is absent, so a download failure here is
# non-fatal -- matcher-only mode still works.
install_nuclei() {
  if [ -x "$INSTALL_DIR/bin/nuclei" ]; then
    echo "[secagent] nuclei already present"
    return 0
  fi
  echo "[secagent] Downloading nuclei CLI for $OS/$ARCH..."
  mkdir -p "$INSTALL_DIR/bin"
  local NUCLEI_VER="${NUCLEI_VER:-v3.4.5}"
  local TARBALL="nuclei_${NUCLEI_VER#v}_${OS}_${ARCH}.tar.gz"
  local URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/${TARBALL}"
  local TMP_TGZ
  TMP_TGZ="$(mktemp --suffix=.tgz)"
  if curl -fsSL -o "$TMP_TGZ" "$URL"; then
    if tar -xzf "$TMP_TGZ" -C "$INSTALL_DIR/bin" 2>/dev/null; then
      chmod +x "$INSTALL_DIR/bin/nuclei" 2>/dev/null || true
      if [ -x "$INSTALL_DIR/bin/nuclei" ]; then
        echo "[secagent] nuclei installed: $("$INSTALL_DIR/bin/nuclei" -version 2>/dev/null | head -1)"
      else
        echo "[secagent] Warning: nuclei tarball extracted but binary not found"
      fi
    else
      echo "[secagent] Warning: failed to extract nuclei tarball; matcher-only mode"
    fi
  else
    echo "[secagent] Warning: nuclei download failed; matcher-only mode"
  fi
  rm -f "$TMP_TGZ"
}
install_nuclei || true


# Install systemd service
cat > /etc/systemd/system/secagent.service << EOFSVC
[Unit]
Description=Security Agent
Documentation=https://github.com/security-agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/agent
Restart=always
RestartSec=10
LimitNOFILE=65536
Environment="CONFIG_PATH=$CONFIG_DIR/config.json"

[Install]
WantedBy=multi-user.target
EOFSVC

systemctl daemon-reload
systemctl enable secagent
systemctl start secagent

echo "[secagent] Installation complete. Agent is running."
echo "[secagent] Check status: systemctl status secagent"
echo "[secagent] View logs: journalctl -u secagent -f"
