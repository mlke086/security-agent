"""阶段 3-1 冒烟:ai app uvicorn 启动,获取 OpenAPI 真实路径。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.ai.main import app

config = uvicorn.Config(app, host="127.0.0.1", port=18001, log_level="error")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.2)
try:
    resp = urllib.request.urlopen("http://127.0.0.1:18001/healthz", timeout=5)
    print("healthz:", resp.status, json.loads(resp.read()))
    spec = json.loads(
        urllib.request.urlopen("http://127.0.0.1:18001/openapi.json", timeout=5).read()
    )
    paths = sorted(spec["paths"].keys())
    print("paths:", paths)
    print("total endpoints:", sum(len(v) for v in spec["paths"].values()))
finally:
    server.should_exit = True
    t.join(timeout=3)
print("done")