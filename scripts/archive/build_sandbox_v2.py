"""Build sandbox: upload Dockerfile + build with proxy on remote."""
import paramiko

HOST = "192.168.80.101"
PASS = "615700"
PROXY = "http://192.168.254.121:7897"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, port=22, username="root", password=PASS, timeout=15)

# Upload updated Dockerfile
sftp = ssh.open_sftp()
sftp.put("deployments/docker/Dockerfile.sandbox", "/tmp/sandbox-build/Dockerfile")
sftp.close()

def run(cmd, timeout=180):
    s, o, e = ssh.exec_command(cmd, timeout=timeout)
    rc = o.channel.recv_exit_status()
    return rc, o.read().decode().strip(), e.read().decode().strip()

PROXY_ARG = proxy_arg = 'http://192.168.254.121:7897'

print("Uploaded Dockerfile. Building...")
rc, o, e = run(
    "docker build "
    "--build-arg http_proxy=" + PROXY + " "
    "--build-arg https_proxy=" + PROXY + " "
    "-t security-agent-sandbox:latest /tmp/sandbox-build/",
    180,
)
if rc == 0:
    print("BUILD SUCCESS")
    run("docker images security-agent-sandbox --format '{{.Repository}}:{{.Tag}} {{.Size}}'")
else:
    print(f"BUILD FAILED: {e[:400]}")

# Verify
rc, o, e = run("docker run --rm security-agent-sandbox -c \"import requests; print('requests:', requests.__version__)\"", 15)
print(o)

ssh.close()
print("Done")
