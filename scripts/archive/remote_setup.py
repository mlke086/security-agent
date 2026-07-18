"""S2-2/3: Remote Docker build + Kafka verification on 192.168.80.101."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=120):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    err = stderr.read().decode()
    rc = stdout.channel.recv_exit_status()
    return rc, out.strip(), err.strip()

# 1. Build sandbox in clean dir
print("=== Build Sandbox Image ===")
sftp = ssh.open_sftp()
try:
    sftp.mkdir("/tmp/sandbox-build")
except:
    pass
with sftp.open("/tmp/sandbox-build/Dockerfile", "w") as f:
    f.write("""FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir requests==2.31.0 urllib3==2.2.0 && rm -rf /root/.cache/pip
RUN groupadd -r sandbox && useradd -r -g sandbox sandbox
USER sandbox
WORKDIR /home/sandbox
ENTRYPOINT ["python3", "-I"]
CMD ["-c", "print('sandbox ready')"]
""")
sftp.close()

rc, out, err = run("cd /tmp/sandbox-build && docker build -t security-agent-sandbox:latest .", timeout=120)
if rc == 0:
    print("Build SUCCESS")
    run("docker images security-agent-sandbox --format '{{.Repository}}:{{.Tag}} {{.Size}}'")
else:
    print(f"Build FAILED: {err[:300]}")

# 2. Verify image
print()
rc, out, err = run("docker images security-agent-sandbox --format '{{.Repository}}:{{.Tag}} {{.Size}}'")
print(f"Image: {out}")

# 3. Test Kafka via docker exec
print("\n=== Kafka Verification ===")
rc, out, err = run("docker exec kafka sh -c 'kafka-topics.sh --bootstrap-server localhost:9092 --list'", timeout=10)
if rc == 0:
    print(f"Topics: {out}")
else:
    print(f"Kafka cmd failed: {err[:200]}")

# 4. Verify network
print()
rc, out, err = run("docker network inspect sandbox-net --format '{{.Name}} {{.Driver}} {{.Scope}}'")
print(f"Network: {out}")

# 5. Verify all middleware containers are healthy
print("\n=== Middleware Status ===")
rc, out, err = run("docker ps --filter health=healthy --format '{{.Names}}'")
containers = [c.strip() for c in out.split("\n") if c.strip()]
for c in containers:
    print(f"  [HEALTHY] {c}")

ssh.close()
print("\n=== Remote Tasks Complete ===")
