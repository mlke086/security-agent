"""全面功能测试 - 事件端到端链路 + scan-engine。

链路:gateway POST /api/v1/events → Redis Stream events:tasks → scan-engine
events consumer → LangGraph 流水线 → 事件状态回写 ES。
"""
import json
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "V:/project/security-agent")

GW = "http://127.0.0.1:18000"
SE = "http://127.0.0.1:18003"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail[:120]}")


def req(base: str, method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 15):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    if body is not None:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
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

    # 1. scan-engine healthz(task_worker + events_consumer 双 alive)
    s, b = req(SE, "GET", "/healthz")
    check("scan-engine healthz", s == 200 and b.get("task_worker_alive") and b.get("events_consumer_alive"), str(b)[:100])

    # 2. scan-engine /metrics(含 taskworker_lag)
    s, b = req(SE, "GET", "/metrics")
    body = b if isinstance(b, (str, bytes)) else str(b)
    check("scan-engine /metrics", s == 200 and "taskworker_lag" in str(body), f"{s} len={len(str(body))}")

    # 3. 事件端到端:gateway 提交 → scan-engine 消费 → 流水线
    s, b = req(GW, "POST", "/api/v1/events", {
        "sanitized_text": "可疑登录:user admin from 203.0.113.9 尝试 SSH 爆破",
        "iocs": {"ips": ["203.0.113.9"]},
        "source": "manual",
    }, token=admin)
    check("gateway events submit", s == 200 and b.get("status") == "processing", f"{s} {str(b)[:80]}")
    evt_id = b.get("event_id", "")
    check("event_id present", bool(evt_id), evt_id)

    # 4. 轮询事件状态(scan-engine 消费 + 流水线,最多 60s)
    if evt_id:
        states = []
        for i in range(30):
            s, b = req(GW, "GET", f"/api/v1/events/{evt_id}", token=admin)
            st = b.get("status", "") if isinstance(b, dict) else ""
            states.append(st)
            if st in ("completed", "error", "ignored", "timeout"):
                break
            time.sleep(2)
        check("event pipeline terminal", bool(states) and states[-1] in ("completed", "error", "ignored", "timeout"), f"states={states[-3:]}")
        check("event trace steps", isinstance(b, dict) and len(b.get("trace", [])) >= 1, f"steps={len(b.get('trace', [])) if isinstance(b, dict) else 0}")

    # 5. Redis stream 确认已消费(无残留 pending)
    import asyncio
    import redis.asyncio as aioredis

    async def check_stream():
        r = aioredis.from_url("redis://:redis_password_2026@192.168.80.101:6379/0", decode_responses=True)
        try:
            groups = await r.xinfo_groups("events:tasks")
            pend = sum(g.get("pending", 0) for g in groups)
            return pend
        except Exception:
            return -1
        finally:
            await r.aclose()

    pend = asyncio.run(check_stream())
    check("events:tasks no pending", pend == 0, f"pending={pend}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
