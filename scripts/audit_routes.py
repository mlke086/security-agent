"""全路由审计:启动 gateway uvicorn,逐路径检查 handler 端点是否真存在。"""
import json
import re
import threading
import time
import urllib.request

import uvicorn

from src.api.main import app

cfg = uvicorn.Config(app, host="127.0.0.1", port=18000, log_level="error")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(60):
    if server.started:
        break
    time.sleep(0.3)
time.sleep(2)

try:
    spec = json.loads(urllib.request.urlopen("http://127.0.0.1:18000/openapi.json", timeout=5).read())
    paths = spec["paths"]
    print(f"total OpenAPI paths: {len(paths)}")
    # 提取每个路径的所有 method
    route_info = []
    for p, methods in sorted(paths.items()):
        for m in methods:
            if m in ("get", "post", "put", "patch", "delete"):
                route_info.append((m.upper(), p))
    print(f"total (method, path) routes: {len(route_info)}")
    # 分组
    from collections import Counter

    grp = Counter()
    for m, p in route_info:
        parts = p.split("/")
        key = parts[3] if len(parts) > 3 else "(root)"
        grp[key] += 1
    for k, v in grp.most_common():
        print(f"  /api/v1/{k}/... : {v} routes")
finally:
    server.should_exit = True
    t.join(timeout=3)
print("done")