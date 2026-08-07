"""阶段 3-4 调试 2:开启 gateway proxy 日志,看反代链日志。"""
import json
import logging
import threading
import time

import structlog
import uvicorn

# 配置 structlog 输出到 stderr 便于看到
logging.basicConfig(level=logging.INFO)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))

from src.ai.main import app as ai_app
from src.api.main import app as gw_app


def _boot(app, port, label):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True, name=label)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    return server, t


gw_server, gw_thread = _boot(gw_app, 18000, "gateway")
ai_server, ai_thread = _boot(ai_app, 18001, "ai")

time.sleep(3)  # 充分就绪

try:
    import urllib.request, urllib.error

    # 直接调 gateway
    req = urllib.request.Request(
        "http://127.0.0.1:18000/api/v1/chat",
        data=json.dumps({"text": "hi"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"GATEWAY STATUS: {resp.status}")
            print(f"GATEWAY HEADERS: {dict(resp.headers)}")
            print(f"GATEWAY BODY: {resp.read()[:300]}")
    except urllib.error.HTTPError as e:
        print(f"GATEWAY HTTPError: status={e.code} reason={e.reason}")
        print(f"GATEWAY HEADERS: {dict(e.headers)}")
        print(f"GATEWAY BODY: {e.read()[:300]}")
finally:
    gw_server.should_exit = True
    ai_server.should_exit = True
    gw_thread.join(timeout=3)
    ai_thread.join(timeout=3)
print("done")