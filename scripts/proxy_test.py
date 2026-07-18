"""Simple proxy test + Docker build on remote."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=15)

def run(cmd, timeout=30):
    s, o, e = ssh.exec_command(cmd, timeout=timeout)
    return o.channel.recv_exit_status(), o.read().decode().strip(), e.read().decode().strip()

PROXY = "http://192.168.254.121:7897"

# Test 1: curl via proxy
rc, o, e = run("curl -so /dev/null -w '%{http_code}' --proxy " + PROXY + " --max-time 10 https://pypi.org")
print(f"Proxy test (HTTP code): {o}")

# Test 2: Docker run with -e proxy
rc, o, e = run("docker run --rm -e http_proxy=" + PROXY + " python:3.11-slim sh -c 'pip install requests 2>&1'", 60)
if rc == 0:
    print("Docker pip: SUCCESS")
else:
    print(f"Docker pip: FAILED")
    print(f"  {o[-300:]}")

# Test 3: check if the proxy IP is reachable at all
rc, o, e = run("ping -c 2 -W 3 192.168.254.121 2>&1 | head -3")
print(f"Ping proxy: {o[:100]}")

ssh.close()
