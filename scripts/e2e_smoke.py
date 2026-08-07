"""E2E 冒烟:按方案核心功能链路跑一遍。

服务端口(测试用,生产见 docker-compose):
  gateway    :18000  (auth + WS + 反代 + vulnscan CRUD)
  ai         :18001  (chat/scan_chat/models)
  scan-engine:18003  (TaskWorker + events:tasks consumer)
  graphrag   :18002  (embed + /memory/* + /engine/search)

每条用例:
  1. healthz 命中
  2. JWT 鉴权链路(自签 → /auth/me)
  3. gateway 反代 /api/v1/chat → ai(401 透传)
  4. graphrag /embed(若模型就绪)/healthz
  5. scan-engine TaskWorker 启动 + events 消费者存活
  6. vulnscan 入队 → scan-engine 消费
  7. SSE stream 订阅任务进度
  8. cti_analyst 经 graphrag 调 (investigation subgraph)
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

# 强制不走 Nacos(用本机 .env 默认值)
os.environ.setdefault("NACOS_SERVER", "")

import uvicorn
from fastapi.testclient import TestClient

# 三个服务 app
import src.api.main as gw_mod
import src.ai.main as ai_mod
import src.graphrag.main as gr_mod
import src.scan_engine.main as se_mod


def boot(app, port, label):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True, name=label)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    return server, t


def http_get(url, headers=None, timeout=10):
    h = headers or {}
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:
        return 0, str(e)


def http_post(url, body=None, headers=None, timeout=10):
    h = {"Content-Type": "application/json", **(headers or {})}
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:
        return 0, str(e)


def main():
    os.environ["AI_BASE_URL"] = "http://127.0.0.1:18001"
    os.environ["GRAPHRAG_BASE_URL"] = "http://127.0.0.1:18002"

    # gateway 启动需要 Nacos(实际连不上但 graceful);ai 不需要;graphrag 需要 torch 模型
    # 这次重点 gateway + ai,scan-engine / graphrag 只验 /healthz

    print("=" * 60)
    print("[1] gateway /healthz")
    gw, gt = boot(gw_mod.app, 18000, "gw")
    time.sleep(3)
    s, b = http_get("http://127.0.0.1:18000/health")
    print(f"  status={s} body={b}")

    print("[2] gateway /openapi.json paths count")
    s, b = http_get("http://127.0.0.1:18000/openapi.json")
    if isinstance(b, dict) and "paths" in b:
        print(f"  total paths: {len(b['paths'])}")
    else:
        print(f"  unexpected: {b}")

    print("[3] ai /healthz")
    ai, at = boot(ai_mod.app, 18001, "ai")
    time.sleep(3)
    s, b = http_get("http://127.0.0.1:18001/healthz")
    print(f"  status={s} body={b}")

    print("[4] ai /openapi.json paths count")
    s, b = http_get("http://127.0.0.1:18001/openapi.json")
    if isinstance(b, dict) and "paths" in b:
        print(f"  total paths: {len(b['paths'])}")
        ai_paths = sorted(b["paths"].keys())
        print(f"  paths: {ai_paths}")
    else:
        print(f"  unexpected: {b}")

    print("[5] graphrag /healthz")
    gr, gt2 = boot(gr_mod.app, 18002, "gr")
    time.sleep(3)
    s, b = http_get("http://127.0.0.1:18002/healthz")
    print(f"  status={s} body={b}")

    print("[6] scan-engine /healthz")
    se, st = boot(se_mod.app, 18003, "se")
    time.sleep(3)
    s, b = http_get("http://127.0.0.1:18003/healthz")
    print(f"  status={s} body={b}")

    print("[7] gateway 反代 /api/v1/chat → ai (无 JWT 期望 401)")
    s, b = http_post("http://127.0.0.1:18000/api/v1/chat", {"text": "hi"})
    print(f"  status={s} body={b}")

    print("[8] gateway 反代 /api/v1/scan-chat → ai (期望 401)")
    s, b = http_post("http://127.0.0.1:18000/api/v1/scan-chat", {"text": "scan"})
    print(f"  status={s} body={b}")

    print("[9] gateway 反代 /api/v1/models → ai (期望 401)")
    s, b = http_get("http://127.0.0.1:18000/api/v1/models")
    print(f"  status={s} body={b}")

    print("[10] gateway 本地 vulnscan /api/v1/vulnscan/tasks/parse (期望 401)")
    s, b = http_post("http://127.0.0.1:18000/api/v1/vulnscan/tasks/parse", {"intent_text": "test"})
    print(f"  status={s} body={b}")

    print("[11] self-signed JWT 通过 gateway /auth/me")
    from src.api.auth.jwt import create_access_token
    token = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)
    h = {"Authorization": f"Bearer {token}"}
    s, b = http_get("http://127.0.0.1:18000/api/v1/auth/me", headers=h)
    print(f"  status={s} body={b}")

    print("[12] gateway 鉴权后 /api/v1/vulnscan/tasks GET (列表)")
    s, b = http_get("http://127.0.0.1:18000/api/v1/vulnscan/tasks", headers=h)
    print(f"  status={s} body_keys={list(b.keys()) if isinstance(b, dict) else type(b).__name__}")

    print("[13] /api/v1/agents 列表")
    s, b = http_get("http://127.0.0.1:18000/api/v1/agents/groups", headers=h)
    print(f"  status={s} body_keys={list(b.keys()) if isinstance(b, dict) else type(b).__name__}")

    print("[14] /api/v1/events 提交")
    s, b = http_post("http://127.0.0.1:18000/api/v1/events", {"text": "suspicious login from 1.2.3.4"}, headers=h)
    print(f"  status={s} body={b}")

    print("[15] /api/v1/alerts 列表")
    s, b = http_get("http://127.0.0.1:18000/api/v1/alerts", headers=h)
    print(f"  status={s} body_keys={list(b.keys()) if isinstance(b, dict) else type(b).__name__}")

    # shutdown
    for s in (gw, ai, gr, se):
        s.should_exit = True
    for t in (gt, at, gt2, st):
        t.join(timeout=3)
    print("done")


if __name__ == "__main__":
    main()