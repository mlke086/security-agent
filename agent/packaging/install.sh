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

# V10 阶段 5.2 / V12 阶段 5.4: send the token via Authorization header
# instead of a ?token= query param. A query param is visible in process
# lists / shell history / proxy logs; the header is not. The console
# endpoints (api_download_ca / api_download_binary) read _extract_token
# which prefers the header when present.
AUTH_HEADER="Authorization: Bearer $TOKEN"

# Download CA certificate
echo "[secagent] Downloading CA certificate..."
curl -fsSL -H "$AUTH_HEADER" "$CONSOLE/api/v1/agents/ca" -o "$CONFIG_DIR/ca.pem" || echo "[secagent] Warning: no CA cert"

# Download agent binary
echo "[secagent] Downloading agent binary for $OS/$ARCH..."
curl -fsSL -H "$AUTH_HEADER" "$CONSOLE/api/v1/agents/binary/$OS/$ARCH" -o "$INSTALL_DIR/agent"
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
# V10 阶段 3.4 (V12): config.json contains the enroll_token in plaintext;
# restrict it to the agent user so other local users / world-readable logs
# can't harvest the token. (enroll.py does the same chmod 0600 on the
# server-generated path.)
chmod 600 "$CONFIG_DIR/config.json"
# P0 (2026-07-18): Install the nuclei CLI alongside the agent so the
# "nuclei" scan engine can run. The agent itself falls back to its own
# matcher when nuclei is absent, so a download failure here is
# non-fatal -- matcher-only mode still works.
#
# 2026-07-30: download from an internal nginx mirror (NUCLEI_BASE /
# NUCLEI_VER, overridable via env) instead of GitHub, which is unreachable
# from many CN networks. The server-generated install script (enroll.py)
# injects the Nacos-configured values; this standalone copy falls back to
# sensible defaults so it still works without the console.
install_nuclei() {
  if [ -x "$INSTALL_DIR/bin/nuclei" ]; then
    echo "[secagent] nuclei already present"
    return 0
  fi
  local NUCLEI_BASE="${NUCLEI_BASE:-http://192.168.80.101:8081}"
  local NUCLEI_VER="${NUCLEI_VER:-3.11.0}"
  local NUCLEI_ZIP="nuclei_${NUCLEI_VER}_${OS}_${ARCH}.zip"
  echo "[secagent] Downloading nuclei CLI v${NUCLEI_VER} from internal mirror..."
  mkdir -p "$INSTALL_DIR/bin"
  local TMPD
  TMPD="$(mktemp -d)"
  if curl -fsSL -o "$TMPD/$NUCLEI_ZIP" "${NUCLEI_BASE}/${NUCLEI_ZIP}"; then
    (cd "$TMPD" && (command -v unzip >/dev/null && unzip -o "$NUCLEI_ZIP" \
        || python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall('.')" "$NUCLEI_ZIP")) 2>/dev/null
    if [ -x "$TMPD/nuclei" ] || [ -x "$TMPD/nuclei.exe" ]; then
      local BIN_NAME="nuclei"
      [ "$OS" = "windows" ] && BIN_NAME="nuclei.exe"
      install -m 0755 "$TMPD/$BIN_NAME" "$INSTALL_DIR/bin/$BIN_NAME" 2>/dev/null || true
      echo "[secagent] nuclei v${NUCLEI_VER} installed: $("$INSTALL_DIR/bin/$BIN_NAME" -version 2>/dev/null | head -1)"
    else
      echo "[secagent] Warning: nuclei zip extracted but binary not found"
    fi
  else
    echo "[secagent] Warning: nuclei download failed; matcher-only mode"
  fi
  rm -rf "$TMPD"
}
install_nuclei || true

# Install nuclei-templates from the same internal mirror so a fresh host can
# run real nuclei scans without waiting for the console「同步 Nuclei 模板」
# button. Best-effort: failure leaves matcher-only mode working. The zip wraps
# content in a top-level nuclei-templates-<ver>/ dir; we strip it so categories
# (cves/, exposures/, ...) land directly under templates/ where nuclei -t reads.
install_nuclei_templates() {
  if [ -d "$INSTALL_DIR/templates/cves" ] || [ -d "$INSTALL_DIR/templates/exposures" ]; then
    echo "[secagent] nuclei templates already present"
    return 0
  fi
  local NUCLEI_BASE="${NUCLEI_BASE:-http://192.168.80.101:8081}"
  local NUCLEI_TPL_VER="${NUCLEI_TPL_VER:-10.4.6}"
  local TPL_ZIP="nuclei-templates-${NUCLEI_TPL_VER}.zip"
  echo "[secagent] Downloading nuclei-templates v${NUCLEI_TPL_VER} from internal mirror..."
  mkdir -p "$INSTALL_DIR/templates"
  local TMPD
  TMPD="$(mktemp -d)"
  if curl -fsSL -o "$TMPD/$TPL_ZIP" "${NUCLEI_BASE}/${TPL_ZIP}"; then
    (cd "$TMPD" && (command -v unzip >/dev/null && unzip -o "$TPL_ZIP" \
        || python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall('.')" "$TPL_ZIP")) 2>/dev/null
    local WRAPPER="$TMPD/nuclei-templates-${NUCLEI_TPL_VER}"
    if [ -d "$WRAPPER" ]; then
      cp -r "$WRAPPER/." "$INSTALL_DIR/templates/" 2>/dev/null
    else
      cp -r "$TMPD/." "$INSTALL_DIR/templates/" 2>/dev/null
    fi
    if [ -d "$INSTALL_DIR/templates/cves" ] || [ -d "$INSTALL_DIR/templates/exposures" ]; then
      echo "[secagent] nuclei-templates v${NUCLEI_TPL_VER} installed at $INSTALL_DIR/templates"
    else
      echo "[secagent] Warning: nuclei-templates extracted but no category dirs found"
    fi
  else
    echo "[secagent] Warning: nuclei-templates download failed; matcher-only mode"
  fi
  rm -rf "$TMPD"
}
install_nuclei_templates || true


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
RestartPreventExitStatus=0
# 主动下线（agent_shutdown）→ exit 0 → systemd 不重启
# 进程 crash / panic / OOM → exit≠0 → systemd 自动重启
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
