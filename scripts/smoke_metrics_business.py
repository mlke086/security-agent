"""P2-10 验证:gateway /metrics 含 ai_unreachable_total,graphrag /metrics 含 graphrag_embed_latency_seconds。"""
import json
import threading
import time
import urllib.request

import uvicorn

from src.api.main import app as gw_app
from src.graphrag.main import app as gr_app

cfg1 = uvicorn.Config(gw_app, host="127.0.0.1", port=18000, log_level="error")
s1 = uvicorn.Server(cfg1)
t1 = threading.Thread(target=s1.run, daemon=True)
t1.start()
cfg2 = uvicorn.Config(gr_app, host="127.0.0.1", port=18002, log_level="error")
s2 = uvicorn.Server(cfg2)
t2 = threading.Thread(target=s2.run, daemon=True)
t2.start()
for _ in range(50):
    if s1.started and s2.started:
        break
    time.sleep(0.3)
time.sleep(2)

b_gw = urllib.request.urlopen("http://127.0.0.1:18000/metrics", timeout=5).read().decode()
print("gateway /metrics has ai_unreachable_total:", "ai_unreachable_total" in b_gw)
print("gateway /metrics has graphrag_embed_latency:", "graphrag_embed_latency" in b_gw)

b_gr = urllib.request.urlopen("http://127.0.0.1:18002/metrics", timeout=5).read().decode()
print("graphrag /metrics has graphrag_embed_latency_seconds:", "graphrag_embed_latency_seconds" in b_gr)
print("graphrag /metrics has taskworker_lag:", "taskworker_lag" in b_gr)

s1.should_exit = True
s2.should_exit = True
t1.join(timeout=3)
t2.join(timeout=3)
print("done")