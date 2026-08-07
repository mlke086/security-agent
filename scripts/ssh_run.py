"""SSH 连通性验证 + 远程命令执行工具。"""
import sys

import paramiko

HOST = "192.168.80.101"
USER = "root"
PASS = "615700"


def run(commands: list[str]) -> None:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST, port=22, username=USER, password=PASS, timeout=8)
        print(f"SSH OK -> {HOST}")
        for cmd in commands:
            stdin, stdout, stderr = c.exec_command(cmd, timeout=20)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            print(f"$ {cmd}")
            if out:
                print(out)
            if err:
                print(f"[stderr] {err}")
    except Exception as e:
        print(f"SSH FAIL: {e}")
        sys.exit(1)
    finally:
        c.close()


if __name__ == "__main__":
    run([
        "hostname",
        "docker ps --format '{{.Names}}' 2>/dev/null | head -20",
    ])
