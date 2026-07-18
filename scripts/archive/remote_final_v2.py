"""Final remote setup: tag base image as sandbox + verify Kafka."""
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.80.101", port=22, username="root", password="615700", timeout=10)

def run(cmd, timeout=30):
    s, o, e = ssh.exec_command(cmd, timeout=timeout)
    rc = o.channel.recv_exit_status()
    return rc, o.read().decode().strip(), e.read().decode().strip()

# 1. Tag python:3.11-slim as our sandbox image
print("=== Sandbox Image ===")
rc, o, e = run("docker tag python:3.11-slim security-agent-sandbox 2>/dev/null; docker images security-agent-sandbox --format '{{.Repository}}= {{.Size}}'", 10)
print(f"Image: {o}")
if not o:
    # Pull and tag
    run("docker pull python:3.11-slim", 60)
    run("docker tag python:3.11-slim security-agent-sandbox", 10)
    run("docker images security-agent-sandbox --format '{{.Repository}}= {{.Size}}'", 10)
    print("Tagged python:3.11-slim as security-agent-sandbox")

# 2. Verify sandbox works
rc, o, e = run("docker run --rm security-agent-sandbox -c 'print(1+1)'", 10)
print(f"Sandbox test: {o} (expected: 2)")

# 3. Kafka test
print("\n=== Kafka Producer Test ===")
run("pip3 install kafka-python 2>&1 | tail -1", 30)
rc, o, e = run('python3 -c "from kafka import KafkaProducer; p=KafkaProducer(bootstrap_servers=[chr(108)+chr(111)+chr(99)+chr(97)+chr(108)+chr(104)+chr(111)+chr(115)+chr(116)+chr(58)+chr(57)+chr(48)+chr(57)+chr(50)]); p.send(chr(114)+chr(97)+chr(119)+chr(45)+chr(97)+chr(108)+chr(101)+chr(114)+chr(116)+chr(115), b\"test\"); p.flush(); p.close(); print(chr(79)+chr(75))"', 15)
print(f"Producer: {o[:200]}")

# 4. List Kafka topics
rc, o, e = run("docker exec kafka sh -c '/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list'", 10)
print(f"Topics: {o}")

ssh.close()
print("\nAll done!")
