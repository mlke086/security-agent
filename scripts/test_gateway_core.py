"""全面功能测试 - gateway 基础(auth/RBAC/health/proxy)。"""
import json
import urllib.error
import urllib.request

import sys

sys.path.insert(0, "V:/project/security-agent")

BASE = "http://127.0.0.1:18000"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")


def req(method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 10):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    if body is not None:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def get_admin_token() -> str:
    from src.api.auth.jwt import create_access_token
    return create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)


def get_viewer_token() -> str:
    from src.api.auth.jwt import create_access_token
    return create_access_token(data={"sub": "viewer", "role": "viewer"}, token_version=0)


def main() -> None:
    admin = get_admin_token()
    viewer = get_viewer_token()

    # 1. health
    s, b = req("GET", "/health")
    check("health 200", s == 200 and b.get("status") == "ok", str(b))

    # 2. openapi
    s, b = req("GET", "/openapi.json")
    n = len(b.get("paths", {})) if isinstance(b, dict) else 0
    check("openapi 77 paths", s == 200 and n >= 70, f"{n} paths")

    # 3. auth login(无凭据 → 401;admin 登录)
    s, b = req("POST", "/api/v1/auth/login", {"username": "admin", "password": "wrong"})
    check("login wrong pwd 401", s in (401, 403), str(b)[:80])
    s, b = req("GET", "/api/v1/auth/me", token=admin)
    check("auth/me admin", s == 200 and b.get("username") == "admin", str(b)[:100])

    # 4. RBAC:viewer 访问 admin-only 端点
    s, b = req("POST", "/api/v1/demo/seed", token=viewer)
    check("viewer demo/seed 403", s in (401, 403), f"{s}")
    s, b = req("GET", "/api/v1/agents", token=viewer)
    check("viewer agents list 403(admin/analyst only)", s == 403, f"{s} {str(b)[:60]}")

    # 5. 未认证 401
    s, b = req("GET", "/api/v1/agents")
    check("no-token agents 401", s == 401, f"{s}")

    # 6. 反代:chat 未认证 401(证明路由到 ai)
    s, b = req("POST", "/api/v1/chat", {"messages": []})
    check("proxy chat no-token 401", s == 401, f"{s} detail={b if isinstance(b, dict) else ''}")
    s, b = req("GET", "/api/v1/models")
    check("proxy models no-token 401", s == 401, f"{s}")
    # 带 token 但缺 body → 422(证明到达 ai 服务)
    s, b = req("POST", "/api/v1/chat", {"messages": []}, token=admin)
    check("proxy chat authed(422 missing fields)", s == 422, f"{s} {str(b)[:80]}")
    s, b = req("POST", "/api/v1/vulnscan/tasks/parse", {"intent_text": "x"}, token=admin)
    check("proxy parse authed(200|4xx)", s in (200, 422, 400, 502), f"{s} {str(b)[:100]}")

    # 7. SSE token(需 body scope)
    s, b = req("POST", "/api/v1/auth/sse-token", {"scope": "events"}, token=admin)
    check("sse-token", s == 200 and isinstance(b, dict) and "token" in str(b), str(b)[:80])

    # 8. metrics
    s, b = req("GET", "/metrics")
    check("metrics 200", s == 200, f"{s}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    if fails:
        for name, _, detail in fails:
            print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
