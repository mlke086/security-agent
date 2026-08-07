#!/bin/sh
# 阶段 5 收尾 P3-10:端口预检脚本
#
# 用法:
#   bash scripts/check_ports.sh            # 检查 8000/8001/8002
#   bash scripts/check_ports.sh --strict   # 端口被占则 exit 1
#
# 输出:三行 OK/PORT-OCCUPIED 状态 + 退出码。
# 退出码:0 全部空闲,1 至少一个端口被占(仅 --strict)
set -u

PORTS="8000 8001 8002"
STRICT=0
if [ "${1:-}" = "--strict" ]; then
    STRICT=1
fi

FAILED=0
for port in $PORTS; do
    # ss 在 Windows + Git Bash 不可用,fallback 到 netstat / python socket
    if command -v ss >/dev/null 2>&1; then
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -E "(^|:)${port}\b" >/dev/null 2>&1; then
            echo "PORT-OCCUPIED  ${port}"
            FAILED=$((FAILED + 1))
        else
            echo "OK              ${port}"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tln 2>/dev/null | awk '{print $4}' | grep -E "(^|:)${port}\b" >/dev/null 2>&1; then
            echo "PORT-OCCUPIED  ${port}"
            FAILED=$((FAILED + 1))
        else
            echo "OK              ${port}"
        fi
    else
        # Python fallback
        if python -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(('127.0.0.1', int('${port}')))
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            echo "PORT-OCCUPIED  ${port}"
            FAILED=$((FAILED + 1))
        else
            echo "OK              ${port}"
        fi
    fi
done

if [ "$STRICT" = "1" ] && [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0