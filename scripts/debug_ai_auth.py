"""调试 3 完整版:启动 ai 服务,测不同 header 下的 /api/v1/chat 响应。"""
import json
import threading
import time
import urllib.error
import urllib.request

import uvicorn

from src.ai.main import app as ai_app


cfg = uvicorn.Config(ai_app, host="127.0.0.1", port=18001, log_level="error")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(80):
    if server.started:
        break
    time.sleep(0.3)
time.sleep(2)  # 等 Nacos/PG 初始化


def _do(method, url, headers=None, body=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


for h in [None, {"Authorization": "Bearer x"}, {"X-Test": "y"}]:
    s, hdrs, body = _do(
        "POST", "http://127.0.0.1:18001/api/v1/chat", headers=h, body={"text": "x"}
    )
    print(f"ai POST /api/v1/chat headers={h}: status={s} body={body[:200]}")


server.should_exit = True
t.join(timeout=3)