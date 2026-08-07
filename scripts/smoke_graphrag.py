"""阶段 1-3 冒烟脚本(graphrag uvicorn 实启动)。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.graphrag.main import app

config = uvicorn.Config(app, host="127.0.0.1", port=18002, log_level="error")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.2)

try:
    resp = urllib.request.urlopen("http://127.0.0.1:18002/healthz", timeout=5)
    print("healthz:", resp.status, json.loads(resp.read()))
    spec = json.loads(
        urllib.request.urlopen("http://127.0.0.1:18002/openapi.json", timeout=5).read()
    )
    print("paths:", sorted(spec["paths"].keys()))
finally:
    server.should_exit = True
    t.join(timeout=3)
print("done")