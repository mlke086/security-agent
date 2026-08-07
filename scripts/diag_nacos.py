"""SSH 拉取 Nacos 配置,检查 store_backend / es 相关覆盖。"""
import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.80.101", port=22, username="root", password="615700", timeout=8)

CMD = r"""
docker exec nacos curl -s "http://localhost:8848/nacos/v1/cs/configs?dataId=security-agent.yaml&group=SECURITY&tenant=prod" 2>/dev/null | grep -E "store_backend|es_hosts|es_index|redis_url|REDIS" | head -30
"""
_, so, se = c.exec_command(CMD, timeout=15)
out = so.read().decode(errors="replace")
print("=== Nacos security-agent.yaml 关键字段 ===")
print(out if out.strip() else "(empty / dataId 不同)")
c.close()
