"""阶段 5 验证:三个 HTTP 服务均暴露 /metrics。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.ai.main import app as ai_app
from src.api.main import app as gw_app
from src.graphrag.main import app as gr_app


def _boot(app, port, label):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True, name=label)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    return server, t


import os

os.environ["AI_BASE_URL"] = "http://127.0.0.1:18001"
from src.common.config.settings import reload_settings

reload_settings()

gw, gt = _boot(gw_app, 18000, "gw")
ai, at = _boot(ai_app, 18001, "ai")
gr, gt2 = _boot(gr_app, 18002, "gr")
time.sleep(3)

try:
    for port, label in [(18000, "gateway"), (18001, "ai"), (18002, "graphrag")]:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/metrics", timeout=5
            ) as resp:
                body = resp.read()[:300]
                # 检查 prometheus 文本格式
                ok = b"process_" in body or b"# HELP" in body
                print(f"[{label}] /metrics status={resp.status} has_prom={ok}")
        except Exception as e:
            print(f"[{label}] /metrics ERROR: {type(e).__name__}: {e}")
finally:
    gw.should_exit = True
    ai.should_exit = True
    gr.should_exit = True
    gt.join(timeout=3)
    at.join(timeout=3)
    gt2.join(timeout=3)
print("done")