"""P2-8 验证:scan-engine /metrics 仍含 taskworker_lag 指标。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.scan_engine.main import app

cfg = uvicorn.Config(app, host="127.0.0.1", port=18004, log_level="error")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.3)
time.sleep(2)

try:
    body = urllib.request.urlopen("http://127.0.0.1:18004/metrics", timeout=5).read().decode()
    has = "taskworker_lag" in body
    print("scan-engine /metrics has taskworker_lag:", has)
finally:
    server.should_exit = True
    t.join(timeout=3)
print("done")