"""阶段 3-4 简化冒烟:分别直连 gateway 和 ai,看每个服务的响应。"""
import json
import threading
import time
import urllib.error
import urllib.request

# 冒烟测试覆盖 ai_base_url:生产是 127.0.0.1:8001,测试用 18001
import os

os.environ["AI_BASE_URL"] = "http://127.0.0.1:18001"

import uvicorn

from src.ai.main import app as ai_app
from src.api.main import app as gw_app

# 在 import main.py 之前覆盖 env,然后强制 settings 单例重建
from src.common.config.settings import reload_settings

reload_settings()


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


def _do(method, url, body=None, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"null")
        except Exception:
            body = None
        return e.code, body


gw_server, gw_thread = _boot(gw_app, 18000, "gateway")
ai_server, ai_thread = _boot(ai_app, 18001, "ai")

try:
    # 1) 直连 ai (期望 401 因为没带 JWT)
    s, b = _do("POST", "http://127.0.0.1:18001/api/v1/chat", {"text": "hi"})
    print(f"[ai direct /api/v1/chat] {s} {b}")

    # 2) gateway /api/v1/chat (期望被反代到 ai,看到 401 而非 404)
    s, b = _do("POST", "http://127.0.0.1:18000/api/v1/chat", {"text": "hi"})
    print(f"[gateway /api/v1/chat (proxy?)] {s} {b}")

    # 3) gateway /health (直接服务)
    s, b = _do("GET", "http://127.0.0.1:18000/health")
    print(f"[gateway /health] {s} {b}")

    # 4) 非 LLM 路径 /api/v1/agents(直接服务,无反代)
    s, b = _do("GET", "http://127.0.0.1:18000/api/v1/agents/groups")
    print(f"[gateway /api/v1/agents/groups (direct)] {s} {b}")
finally:
    gw_server.should_exit = True
    ai_server.should_exit = True
    gw_thread.join(timeout=3)
    ai_thread.join(timeout=3)
print("done")