"""全面功能测试 - 服务启动脚本。

启动 gateway(18000)/ai(18001)/graphrag(18002)/scan-engine(18003)
四个服务,指向 192.168.80.101 的中间件。返回后由测试脚本逐个打端点。
"""
import json
import os
import sys
import threading
import time

os.environ.setdefault("PYTHONPATH", "V:/project/security-agent")
os.environ.setdefault("REDIS_URL", "redis://:redis_password_2026@192.168.80.101:6379/0")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("PG_PORT", "5432")
os.environ.setdefault("PG_DATABASE", "SecAgent")
os.environ.setdefault("PG_USER", "secagent")
os.environ.setdefault("PG_PASSWORD", "Ke615700")
os.environ.setdefault("ES_URL", "http://192.168.80.101:9200")
os.environ.setdefault("NACOS_SERVER", "http://192.168.80.101:8848")
os.environ.setdefault("AI_BASE_URL", "http://127.0.0.1:18001")
os.environ.setdefault("GRAPHRAG_BASE_URL", "http://127.0.0.1:18002")
os.environ.setdefault("DISABLE_TASK_WORKER", "0")

servers: dict[str, threading.Thread] = {}
uvicorn_servers: dict[str, object] = {}


def start_service(name: str, module: str, port: int) -> bool:
    import uvicorn

    # 用独立进程?不,同进程多 app 会共享 Settings 单例。
    # 用 uvicorn 多 worker 不行;这里用线程 + 独立 app 实例会共享模块级单例,
    # 但测试主要是打 HTTP,单例共享在只读路径下可接受。
    from importlib import import_module

    app = import_module(module).app
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    uvicorn_servers[name] = server
    servers[name] = t
    # 等待端口就绪
    import socket

    for _ in range(100):
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            print(f"[started] {name} :{port}")
            return True
        except Exception:
            time.sleep(0.2)
        finally:
            s.close()
    print(f"[FAILED] {name} :{port} not listening")
    return False


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    ok = True
    if mode in ("all", "gateway"):
        ok &= start_service("gateway", "src.api.main", 18000)
    if mode in ("all", "ai"):
        ok &= start_service("ai", "src.ai.main", 18001)
    if mode in ("all", "graphrag"):
        ok &= start_service("graphrag", "src.graphrag.main", 18002)
    if mode in ("all", "scan-engine"):
        ok &= start_service("scan-engine", "src.scan_engine.main", 18003)
    print(f"ALL_STARTED={ok}")
    # 保持进程存活
    if ok:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
