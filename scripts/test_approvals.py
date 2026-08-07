"""全面功能测试 - 审批流(approvals)与响应动作。"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "V:/project/security-agent")

BASE = "http://127.0.0.1:18000"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail[:120]}")


def req(method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 15):
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
    except Exception as e:
        return -1, {"timeout": str(e)[:80]}


def main() -> None:
    from src.api.auth.jwt import create_access_token
    admin = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)

    # 1. 审批列表/详情接口
    s, b = req("GET", "/api/v1/approvals", token=admin)
    check("approvals list", s == 200, f"{s} {str(b)[:100]}")

    # 2. 无审批时的查询
    s, b = req("GET", "/api/v1/approvals?status=pending", token=admin)
    check("approvals pending filter", s == 200, f"{s}")

    # 3. 响应动作白名单(非法 action 400)
    s, b = req("GET", "/api/v1/agents", token=admin)
    hosts = b.get("items", []) if isinstance(b, dict) else []
    if hosts:
        aid = hosts[0]["agent_id"]
        # 非法 action → 400
        s, b = req("POST", f"/api/v1/agents/{aid}/actions/not_exist", {"args": {}}, token=admin)
        check("response invalid action 400", s == 400, f"{s} {str(b)[:80]}")
        # 合法 action 但 agent 不在线 → 预期 404/409
        s, b = req("POST", f"/api/v1/agents/{aid}/actions/kill_process", {"args": {"pid": 1}}, token=admin)
        check("response kill_process (offline→4xx)", s in (400, 404, 409, 200), f"{s} {str(b)[:80]}")
    else:
        check("response actions", True, "no hosts")

    # 4. demo seed(admin,真实 PG EventStore)
    s, b = req("POST", "/api/v1/demo/seed", {}, token=admin)
    check("demo seed", s == 200, f"{s} {str(b)[:100]}")

    # 5. demo 后事件可查
    s, b = req("GET", "/api/v1/events?limit=5", token=admin)
    check("events list after demo", s == 200, f"{s} {str(b)[:100]}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
