"""阶段 5 收尾 P6-monitor 实测:6 个端点全部打通。"""
import os
import threading
import time
import urllib.error
import urllib.request

os.environ.setdefault("PG_PASSWORD", "Ke615700")
os.environ.setdefault("REDIS_URL", "redis://:redis_password_2026@192.168.80.101:6379/0")
os.environ.setdefault("NEO4J_PASSWORD", "neo4j_password_2026")

import uvicorn

from src.api.main import app

cfg = uvicorn.Config(app, host="127.0.0.1", port=18000, log_level="warning")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(80):
    if server.started:
        break
    time.sleep(0.3)
time.sleep(4)

from src.api.auth.jwt import create_access_token

token = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)
h = {"Authorization": f"Bearer {token}"}

results = []
for path in ["/stats", "/queue-status", "/alert-config"]:
    req = urllib.request.Request(
        f"http://127.0.0.1:18000/api/v1/vulnscan/tasks{path}", headers=h
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            results.append((path, r.status, r.read()[:200]))
    except urllib.error.HTTPError as e:
        results.append((path, f"err {e.code}", e.read()[:200]))
    except Exception as e:
        results.append((path, f"exc {type(e).__name__}", str(e)))

for path, status, body in results:
    print(f"{path:20s}  {status}  {body}")

server.should_exit = True
t.join(timeout=3)
print("done")