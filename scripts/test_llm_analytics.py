"""LLM 分析监控功能测试(2026-08-06 新增)。

覆盖:
1. chat_with_retry 三级场景(成功/失败后恢复/全部失败)
2. Redis 指标写入(llm:usage / llm:failures / llm:retry:*)
3. gateway 聚合端点 /api/v1/ai-analytics/llm-usage
4. 补扫达上限 -> 终态标记(AI 全/部分分析失败)
"""
import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "V:/project/security-agent")

os.environ.setdefault("REDIS_URL", "redis://:redis_password_2026@192.168.80.101:6379/0")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("PG_PASSWORD", "Ke615700")

import redis.asyncio as aioredis

REDIS_URL = "redis://:redis_password_2026@192.168.80.101:6379/0"
GW = "http://127.0.0.1:18000"
results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail[:110]}")


async def test_retry_core() -> None:
    from src.scan_engine.llm_analysis import chat_with_retry, _redis, KEY_USAGE, KEY_FAILURES

    # 清理测试数据
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    for k in ["llm:usage", "llm:failures", "llm:active", "llm:retry:lt1", "llm:outcome:lt1"]:
        await r.delete(k)
    await r.aclose()

    # 1) 成功调用
    async def ok_call():
        return "ok"

    res = await chat_with_retry("analyze", ok_call, task_id="lt1", finding_ids=["f1"])
    check("成功调用返回", res == "ok")

    # 2) 失败 2 次后成功(即时重试)
    n = {"c": 0}

    async def flaky_call():
        n["c"] += 1
        if n["c"] < 3:
            raise TimeoutError("llm timeout")
        return "recovered"

    res2 = await chat_with_retry("analyze", flaky_call, task_id="lt1", finding_ids=["f2"])
    check("失败后恢复(3次尝试)", res2 == "recovered" and n["c"] == 3, f"attempts={n['c']}")

    # 3) 全部失败 -> 进补扫队列
    async def bad_call():
        raise RuntimeError("provider 500")

    try:
        await chat_with_retry("analyze", bad_call, task_id="lt1", finding_ids=["f3", "f4"])
        check("全部失败抛异常", False, "should have raised")
    except RuntimeError:
        check("全部失败抛异常", True)

    # 4) Redis 指标
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    usage = await r.hgetall(KEY_USAGE)
    retry = await r.hgetall("llm:retry:lt1")
    fails = await r.lrange(KEY_FAILURES, 0, 5)
    await r.aclose()

    check("usage 成功计数", int(usage.get("2026-08-06:analyze:success", 0)) >= 2, str(usage))
    check("usage 超时计数", int(usage.get("2026-08-06:analyze:timeout", 0)) >= 2, str(usage))
    check("usage 重试计数", int(usage.get("2026-08-06:analyze:retry", 0)) >= 1, str(usage))
    check("usage 失败计数", int(usage.get("2026-08-06:analyze:failed", 0)) >= 3, str(usage))
    check("补扫队列入队", "f3" in retry and "f4" in retry, str(dict(retry)))
    check("失败明细带 error", len(fails) >= 3 and "provider 500" in fails[0], fails[0][:80] if fails else "none")


async def test_gateway_endpoint() -> None:
    from src.api.auth.jwt import create_access_token

    admin = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)
    r = urllib.request.Request(
        GW + "/api/v1/ai-analytics/llm-usage", headers={"Authorization": f"Bearer {admin}"}
    )
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            b = json.loads(resp.read())
    except Exception as e:
        check("gateway llm-usage 端点", False, str(e)[:60])
        return
    check("gateway 端点 200", b["total_calls"] >= 5, f"total={b['total_calls']}")
    check("gateway 聚合成功/超时/失败", b["success"] >= 2 and b["timeout"] >= 2 and b["failed"] >= 3,
          f"s={b['success']} t={b['timeout']} f={b['failed']}")
    check("gateway 失败明细", len(b["failures_recent"]) >= 1, f"n={len(b['failures_recent'])}")
    check("gateway 待补扫", len(b["retry_pending"]) >= 1, f"n={len(b['retry_pending'])}")


async def test_rescan_outcome() -> None:
    import redis.asyncio as aioredis

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    # 模拟已达上限的补扫批次
    await r.hset("llm:retry:lt1", mapping={"f3": "10", "f4": "10"})
    await r.aclose()

    from src.orchestration.subgraphs.vulnscan.rescan import rescan_one_batch

    ret = await rescan_one_batch("lt1")
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    remaining = await r.hlen("llm:retry:lt1")
    outcome = await r.hgetall("llm:outcome:lt1")
    await r.aclose()
    check("达上限清队列", remaining == 0, f"remaining={remaining}")
    check("终态标记写入", "AI" in str(outcome.get("reason", "")), str(dict(outcome)))
    # 清理
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    for k in ["llm:usage", "llm:failures", "llm:active", "llm:retry:lt1", "llm:outcome:lt1"]:
        await r.delete(k)
    await r.aclose()


async def main() -> None:
    await test_retry_core()
    await test_gateway_endpoint()
    await test_rescan_outcome()
    fails = [x for x in results if not x[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    asyncio.run(main())
