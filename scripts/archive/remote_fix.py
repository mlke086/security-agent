"""S2-2/3: Final remote fix — Docker build + Kafka verify."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=60):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err

# 1. Build sandbox — simpler Dockerfile, no version pins
sftp = ssh.open_sftp()
with sftp.open("/tmp/sandbox-build/Dockerfile", "w") as f:
    f.write("FROM python:3.11-slim\n")
    f.write("RUN pip install --no-cache-dir requests urllib3\n")
    f.write("RUN groupadd -r sandbox && useradd -r -g sandbox sandbox\n")
    f.write("USER sandbox\n")
    f.write("WORKDIR /home/sandbox\n")
    f.write('ENTRYPOINT ["python3", "-I"]\n')
sftp.close()

rc, out, err = run("cd /tmp/sandbox-build && docker build -t security-agent-sandbox .", 180)
if rc == 0:
    rc, out, err = run("docker images security-agent-sandbox --format '{{.Repository}} {{.Tag}} {{.Size}}'")
    print(f"Build SUCCESS: {out}")
else:
    print(f"Build FAILED: {err[:300]}")

# 2. Kafka — find and use correct command
cmds = [
    'docker exec kafka sh -c "ls /opt/bitnami/kafka/bin/kafka-topics.sh 2>/dev/null || ls /opt/kafka/bin/kafka-topics.sh 2>/dev/null"',
    'docker exec kafka sh -c "command -v kafka-topics 2>/dev/null || command -v kafka-topics.sh 2>/dev/null"',
    "docker exec kafka sh -c 'kafka-topics --bootstrap-server localhost:9092 --list 2>&1'",
    "docker exec kafka sh -c 'kafka-topics.sh --bootstrap-server localhost:9092 --list 2>&1'",
]
for cmd in cmds:
    rc, out, err = run(cmd, 10)
    if rc == 0 and out:
        print(f"Kafka OK: {cmd.split(chr(39))[1] if chr(39) in cmd else cmd[:60]}")
        print(f"  Topics: {out[:200]}")
        break
    elif err:
        print(f"  Try: {err[:100]}")

# 3. Verify network
rc, out, err = run("docker network inspect sandbox-net --format '{{.Name}} {{.Driver}}'", 5)
print(f"Network: {out}")

ssh.close()
print("\nDone!")
