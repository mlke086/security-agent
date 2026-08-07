"""阶段 3-3 冒烟 v2:gateway uvicorn 实启动,OpenAPI 路径汇总。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.api.main import app

config = uvicorn.Config(app, host="127.0.0.1", port=18000, log_level="error")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(50):
    if server.started:
        break
    time.sleep(0.2)

try:
    spec = json.loads(
        urllib.request.urlopen("http://127.0.0.1:18000/openapi.json", timeout=5).read()
    )
    paths = sorted(spec["paths"].keys())
    print("total paths:", len(paths))

    # 每个 path 提取 HTTP methods
    summary = []
    for p in paths:
        ms = sorted(spec["paths"][p].keys())
        summary.append((p, ms))
    for p, ms in summary:
        print(f"  {ms} {p}")

    # 验证点 1:旧的 chat/models 路由已不再本地注册
    # (chat_router / scan_chat_router / models_router 的 include 已删)
    has_chat = any(p == "/api/v1/chat" for p in paths)
    has_models = any(p == "/api/v1/models" for p in paths)
    print("\nLLM paths in OpenAPI:")
    print("  /api/v1/chat:", has_chat, "(expect False)")
    print("  /api/v1/models:", has_models, "(expect False)")

    # 验证点 2:proxy catch-all 也不应在 schema(include_in_schema=False)
    has_proxy = any("{full_path" in p for p in paths)
    print("  proxy catch-all in OpenAPI:", has_proxy, "(expect False — runtime only)")

    # 验证点 3:vulnscan 仍含 /tasks/parse(保留 gateway 本地)
    has_parse = any(p == "/api/v1/vulnscan/tasks/parse" for p in paths)
    print("  /api/v1/vulnscan/tasks/parse local:", has_parse, "(阶段 3 暂留本地)")
finally:
    server.should_exit = True
    t.join(timeout=3)
print("done")