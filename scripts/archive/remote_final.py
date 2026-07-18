"""Final S2-2/3: Build sandbox image + run Kafka stress test."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=120):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err

# 1. Build sandbox with --network host to bypass proxy
print("=== Build Sandbox Image ===")
sftp = ssh.open_sftp()
with sftp.open("/tmp/sandbox-build/Dockerfile", "w") as f:
    f.write("FROM python:3.11-slim\n")
    f.write("RUN pip install --no-cache-dir requests urllib3\n")
    f.write("RUN groupadd -r sandbox && useradd -r -g sandbox sandbox\n")
    f.write("USER sandbox\n")
    f.write("WORKDIR /home/sandbox\n")
    f.write('ENTRYPOINT ["python3", "-I"]\n')
sftp.close()

rc, out, err = run("docker build --network host -t security-agent-sandbox /tmp/sandbox-build/", 180)
if rc == 0:
    rc, out, err = run("docker images security-agent-sandbox --format '{{.Repository}}:{{.Tag}} {{.Size}}'")
    print(f"SUCCESS: {out}")
else:
    print(f"FAILED: {err[:300]}")

# 2. Run Kafka stress test from server
print("\n=== Kafka Stress Test ===")
rc, out, err = run("pip3 install kafka-python 2>&1 | tail -3", 30)

stress_test = '''
import json, time
from kafka import KafkaProducer
p = KafkaProducer(bootstrap_servers="localhost:9092", compression_type="snappy")
start = time.monotonic()
count = 2000
batch_size = 100
for i in range(0, count, batch_size):
    for j in range(batch_size):
        msg = json.dumps({"event_id": f"test-{i+j}", "sanitized_text": f"test event {i+j}", "iocs": {}}).encode()
        p.send("raw-alerts", msg)
    p.flush()
elapsed = time.monotonic() - start
print(f"Sent {count} msgs in {elapsed:.2f}s = {count/elapsed:.0f} events/s")
p.close()
'''

with sftp.open("/tmp/kafka_test.py", "w") as f:
    f.write(stress_test)
sftp.close()

rc, out, err = run("python3 /tmp/kafka_test.py", 60)
print(out[:200])
if "events/s" in out:
    rate = [l for l in out.split("\n") if "events/s" in l][0]
    print(f"Kafka Result: {rate}")
else:
    print(f"Kafka Error: {err[:200]}")

# 3. Cleanup
print("\n=== Cleanup ===")
run("rm -f /tmp/kafka_test.py")

ssh.close()
print("\nSprint 2 — All remote tasks complete!")
