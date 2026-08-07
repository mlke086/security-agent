"""阶段 3-3 验证:gateway app 启动后,chat/scan_chat/models 三个 LLM router 已不再本地注册,改为 proxy catch-all 兜底。"""
from src.api.main import app


def collect(routes):
    out = []
    for r in routes:
        if hasattr(r, "routes"):
            out.extend(collect(r.routes))
        elif hasattr(r, "path"):
            out.append((r.methods if hasattr(r, "methods") else None, r.path))
    return out


all_routes = collect(app.routes)
print("total:", len(all_routes))
for m, p in sorted(all_routes, key=lambda x: x[1] or ""):
    print(" ", m, p)

# 检查 chat/scan_chat/models 三个 LLM 路由是否在 proxy catch-all 内
# proxy catch-all 路径形如 /api/v1/{full_path:path}
proxy_paths = [p for m, p in all_routes if p and p.startswith("/api/v1/{full_path")]
print("\nproxy catch-all present:", bool(proxy_paths))

# 旧的 chat_router / scan_chat_router / models_router 应不再有具体 /api/v1/chat 等路径
old_llm_paths = [
    p for m, p in all_routes if p in ("/api/v1/chat", "/api/v1/models", "/api/v1/scan-chat")
]
print("old LLM paths still locally registered:", old_llm_paths, "(expect [])")

# vulnscan 仍包含 /tasks/parse(阶段 3 末尾保留)
vulnscan_paths = [p for m, p in all_routes if p and "/vulnscan/tasks/parse" in p]
print("vulnscan /tasks/parse still local:", vulnscan_paths)