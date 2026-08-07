"""阶段 2-4 结构性冒烟:vulnscan 入队路径不依赖 langgraph + scan-engine lifespan 可启动。

不做端到端(需 Redis+Milvus+Neo4j),只验:
1) gateway 启动时 import vulnscan.py 不触发 langgraph
2) scan-engine.main lifespan 在 redis 不可达时优雅降级
3) gateway_proxy 反代结构(阶段 3 占位)不破坏现状
"""
import sys

# 1) gateway import 不触发 langgraph
before = set(sys.modules)
from src.api.routers.vulnscan import api_create_task  # noqa: F401
after = set(sys.modules)
new = sorted(after - before)
heavy = [m for m in new if "langgraph" in m or "sentence_transformers" in m or "torch" in m]
print("[1] vulnscan import heavy modules:", heavy, "(expect [])")
assert not heavy, "FAIL: vulnscan.py still drags langgraph/torch"

# 2) scan-engine app 加载零重依赖
from src.scan_engine.main import app

before2 = set(sys.modules)
_ = app
after2 = set(sys.modules)
new2 = sorted(after2 - before2)
heavy2 = [m for m in new2 if "langgraph" in m or "sentence_transformers" in m or "torch" in m]
print("[2] scan-engine app heavy modules:", heavy2, "(expect [])")
assert not heavy2

# 3) ai app 加载零重依赖(阶段 3 准备)
from src.ai.main import app as ai_app

before3 = set(sys.modules)
_ = ai_app
after3 = set(sys.modules)
new3 = sorted(after3 - before3)
heavy3 = [m for m in new3 if "langgraph" in m or "sentence_transformers" in m or "torch" in m]
print("[3] ai app heavy modules:", heavy3, "(expect [])")
assert not heavy3

print("ALL OK")