"""全面功能测试 - graphrag 服务(按真实 schema)。"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "V:/project/security-agent")

BASE = "http://127.0.0.1:18002"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail[:120]}")


def req(method: str, path: str, body: dict | None = None, timeout: int = 60):
    headers = {"Content-Type": "application/json"} if body is not None else {}
    data = json.dumps(body).encode() if body is not None else None
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
        return -1, {"error": str(e)[:80]}


def main() -> None:
    # 1. healthz
    s, b = req("GET", "/healthz")
    check("healthz", s == 200 and b.get("embedding_dim") == "1024", str(b)[:80])

    # 2. embed(真实 BGE 模型,单 text)
    s, b = req("POST", "/embed", {"text": "扫描 192.168.1.1 发现 SSH 爆破"})
    vector = []
    if s == 200 and isinstance(b, dict):
        vector = b.get("vector", [])
        check("embed", len(vector) == 1024, f"dim={len(vector)}")
    else:
        check("embed", False, f"{s} {str(b)[:100]}")

    # 3. vector-search(需 vector)
    if vector:
        s, b = req("POST", "/vector-search", {"vector": vector[:512], "ioc_values": []})
        check("vector-search", s == 200, f"{s} {str(b)[:100]}")
    else:
        check("vector-search", False, "no vector from embed")

    # 4. graph-query(ioc_values)
    s, b = req("POST", "/graph-query", {"ioc_values": ["192.168.1.1"], "hops": 2})
    check("graph-query", s == 200, f"{s} {str(b)[:100]}")

    # 5. memory add(node + content)
    s, b = req("POST", "/memory/add", {"event_id": "mem-test-001", "node": "investigation", "content": "192.168.1.1 有 SSH 弱口令", "role": "user"})
    check("memory/add", s == 200, f"{s} {str(b)[:100]}")
    # memory search 需要 embedding——先 embed 再 search
    if vector:
        s, b = req("POST", "/memory/search", {"embedding": vector[:512], "top_k": 3})
        check("memory/search", s == 200, f"{s} {str(b)[:100]}")
    else:
        check("memory/search", False, "no vector")
    s, b = req("POST", "/memory/by-event", {"event_id": "mem-test-001"})
    check("memory/by-event", s == 200, f"{s} {str(b)[:100]}")

    # 6. engine/search(ioc_values)
    s, b = req("POST", "/engine/search", {"ioc_values": ["192.168.1.1"], "top_k": 3})
    check("engine/search", s == 200, f"{s} {str(b)[:100]}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
