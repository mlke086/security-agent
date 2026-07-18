"""Debug Docker build and verify Kafka on remote server."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err

# Debug Docker: test basic container run
print("=== Docker Debug ===")
rc, out, err = run("docker run --rm python:3.11-slim python -c 'print(1+1)'", 30)
print(f"Basic test: rc={rc} out={out}")

rc, out, err = run("docker run --rm python:3.11-slim pip --version", 30)
print(f"Pip: {out[:100]}")

rc, out, err = run("docker run --rm python:3.11-slim pip install --no-cache-dir requests", 60)
print(f"Pip install requests: rc={rc}")
if rc != 0:
    print(f"  Error: {err[:200]}")

# If Docker build still fails, try with apk-based image
# Actually let me check the ENV
rc, out, err = run("cat /etc/centos-release 2>/dev/null || cat /etc/os-release 2>/dev/null | head -3", 5)
print(f"OS: {out[:100]}")

# Kafka: list topics with correct binary
print("\n=== Kafka Topics ===")
rc, out, err = run("docker exec kafka sh -c '/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list'", 10)
if rc == 0:
    print(f"Topics: {out}")
else:
    print(f"Error: {err[:200]}")
    # Try with advertised listeners
    rc, out, err = run("docker exec kafka sh -c '/opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list'", 10)
    print(f"Via kafka:9092: rc={rc} out={out[:200]}")

# Create the raw-alerts topic if it doesn't exist
print("\n=== Creating Topic ===")
run("docker exec kafka sh -c '/opt/kafka/bin/kafka-topics.sh --create --topic raw-alerts --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1 2>&1 || true'", 10)
rc, out, err = run("docker exec kafka sh -c '/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list'", 10)
print(f"After create: {out}")

# Django style: use kafka-python from server to test
print("\n=== Python Kafka Test ===")
rc, out, err = run("pip3 install kafka-python 2>&1 | tail -1", 30)
if not err:
    rc, out, err = run("python3 -c \"from kafka import KafkaProducer; p = KafkaProducer(bootstrap_servers='kafka:9092'); p.close(); print('Kafka producer OK')\"", 10)
    print(f"Producer: {out[:200]}")
    rc, out, err = run("python3 -c \"from kafka import KafkaConsumer; c = KafkaConsumer(bootstrap_servers='kafka:9092', request_timeout_ms=5000); print(c.topics()); c.close()\"", 10)
    print(f"Topics: {out[:200]}")

ssh.close()
print("\nDone")
