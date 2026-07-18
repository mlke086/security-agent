"""SSH remote: build sandbox image + verify Kafka."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=60):
    s, o, e = ssh.exec_command(cmd, timeout=timeout)
    rc = o.channel.recv_exit_status()
    return rc, o.read().decode().strip(), e.read().decode().strip()

# Fix Dockerfile to disable proxy inside container
sftp = ssh.open_sftp()
with sftp.open("/tmp/sandbox-build/Dockerfile", "w") as f:
    f.write("FROM python:3.11-slim\n")
    f.write("RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY && pip install --no-cache-dir requests urllib3\n")
    f.write("RUN groupadd -r sandbox && useradd -r -g sandbox sandbox\n")
    f.write("USER sandbox\nWORKDIR /home/sandbox\n")
    f.write('ENTRYPOINT ["python3", "-I"]\n')
sftp.close()

print("=== Build Sandbox ===")
rc, out, err = run("docker build -t security-agent-sandbox /tmp/sandbox-build/", 180)
if rc == 0:
    print("Build SUCCESS")
    run("docker images security-agent-sandbox --format '{{.Repository}}:{{.Tag}} {{.Size}}'")
else:
    print(f"FAILED: {err[:300]}")

print("\n=== Kafka Verify ===")
run("pip3 install kafka-python 2>&1 | tail -1", 30)
rc, out, err = run('python3 -c "from kafka import KafkaProducer; p=KafkaProducer(bootstrap_servers=[\\\"localhost:9092\\\"]); p.send(\\\"raw-alerts\\\", b\\\"hello\\\"); p.flush(); p.close(); print(\\\"OK\\\");"', 10)
print(f"Kafka: {out[:200]}")

print("\n=== Cleanup ===")
ssh.close()
print("All done!")
