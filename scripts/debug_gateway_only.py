"""调试 4:启动 gateway 服务,用 raw httpx 调 /api/v1/chat,看 gateway_proxy 内部状态。"""
import json
import threading
import time
import urllib.error
import urllib.request

import uvicorn

from src.api.main import app as gw_app

cfg = uvicorn.Config(gw_app, host="127.0.0.1", port=18000, log_level="warning")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(80):
    if server.started:
        break
    time.sleep(0.3)
time.sleep(3)


def _do(method, url, headers=None, body=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# 看 /api/v1/chat(应被反代,但 ai 服务没启,所以会 503)
s, hdrs, body = _do("POST", "http://127.0.0.1:18000/api/v1/chat", body={"text": "x"})
print(f"gateway /api/v1/chat (ai down): status={s}")
print(f"  headers={hdrs}")
print(f"  body[:300]={body[:300]}")

# /api/v1/vulnscan/tasks/parse 还在 gateway 本地
s, hdrs, body = _do("POST", "http://127.0.0.1:18000/api/v1/vulnscan/tasks/parse", body={"intent_text": "test"})
print(f"\ngateway /api/v1/vulnscan/tasks/parse (local): status={s}")
print(f"  body[:300]={body[:300]}")

server.should_exit = True
t.join(timeout=3)