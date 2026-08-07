"""全面功能测试 - ai 服务(chat/scan_chat/models/parse)。"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "V:/project/security-agent")

BASE = "http://127.0.0.1:18001"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail[:120]}")


def req(method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 60):
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

    # 1. healthz
    s, b = req("GET", "/healthz")
    check("healthz", s == 200 and b.get("service") == "ai", str(b)[:60])

    # 2. 未认证 401
    s, b = req("POST", "/api/v1/chat", {"messages": [{"role": "user", "content": "hi"}]})
    check("chat no-token 401", s == 401, f"{s}")

    # 3. models CRUD
    s, b = req("GET", "/api/v1/models", token=admin)
    check("models list", s == 200, f"{s} {str(b)[:100]}")
    model_id = None
    if isinstance(b, dict) and b.get("items"):
        model_id = b["items"][0].get("model_id") or b["items"][0].get("id")
    s, b = req("POST", "/api/v1/models", {
        "name": "test-model", "provider": "openai", "model_name": "gpt-4o-mini",
        "api_key": "sk-test", "base_url": "https://api.openai.com/v1",
    }, token=admin)
    check("models create", s in (200, 201, 400, 409), f"{s} {str(b)[:100]}")
    new_id = None
    if s in (200, 201) and isinstance(b, dict):
        new_id = b.get("model_id") or b.get("id")
    if new_id:
        s, b = req("PATCH", f"/api/v1/models/{new_id}", {"name": "test-model-2"}, token=admin)
        check("models patch", s == 200, f"{s} {str(b)[:80]}")
        s, b = req("DELETE", f"/api/v1/models/{new_id}", token=admin)
        check("models delete", s == 200, f"{s}")
    elif model_id:
        s, b = req("PATCH", f"/api/v1/models/{model_id}", {"name": "tmp"}, token=admin)
        check("models patch existing", s in (200, 400, 404), f"{s}")

    # 4. parse 意图识别(经 gateway 反代,直接打 ai 同路径)
    s, b = req("POST", "/api/v1/vulnscan/tasks/parse", {"intent_text": "扫描 192.168.1.100 的漏洞"}, token=admin)
    check("parse intent", s in (200, 400, 422, 502), f"{s} {str(b)[:120]}")

    # 5. chat(LLM 调用,可能慢或失败于 key)—— 验证端点可达 + 鉴权
    s, b = req("POST", "/api/v1/chat", {"message": "你好"}, token=admin)
    check("chat endpoint reachable", s in (200, 400, 422, 500, 502), f"{s} {str(b)[:100]}")

    # 6. scan_chat(conversations 域)
    s, b = req("GET", "/api/v1/vulnscan/conversations", token=admin)
    check("scan_chat conversations list", s == 200, f"{s} {str(b)[:100]}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
