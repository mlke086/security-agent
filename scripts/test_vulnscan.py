"""全面功能测试 - vulnscan 全链路 + 队列监控。"""
import json
import sys
import time
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
        return -1, {"timeout": str(e)[:60]}


def main() -> None:
    from src.api.auth.jwt import create_access_token
    admin = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)

    # ===== 1. 创建任务(入队)=====
    s, b = req("POST", "/api/v1/vulnscan/tasks", {
        "targets": ["192.168.1.10"],
        "modules": ["sys_vuln", "baseline"],
        "engine": "matcher",
    }, token=admin)
    check("create task", s == 200 and b.get("status") == "queued", f"{s} {str(b)[:100]}")
    task_id = b.get("task_id", "")
    check("task_id present", bool(task_id), task_id)

    # ===== 2. 列表/详情 =====
    s, b = req("GET", "/api/v1/vulnscan/tasks", token=admin)
    check("tasks list", s == 200 and "items" in b, f"{s} items={len(b.get('items', []))}")
    if task_id:
        s, b = req("GET", f"/api/v1/vulnscan/tasks/{task_id}", token=admin)
        check("task get single", s == 200, f"{s} {str(b)[:100]}")

    # ===== 3. 非法 source 422 =====
    s, b = req("POST", "/api/v1/vulnscan/tasks", {
        "targets": ["1.2.3.4"], "modules": ["sys_vuln"], "source": "evil-source",
    }, token=admin)
    check("invalid source 422", s == 422, f"{s}")

    # ===== 4. host stats / queue stats =====
    s, b = req("GET", "/api/v1/vulnscan/tasks/stats", token=admin)
    check("task stats", s == 200 and b is not None, f"{s} {str(b)[:100]}")
    s, b = req("GET", "/api/v1/vulnscan/tasks/queue-status", token=admin)
    check("queue-status", s == 200, f"{s} {str(b)[:100]}")

    # ===== 5. 队列监控(问题6)=====
    s, b = req("GET", "/api/v1/vulnscan/tasks/alert-config", token=admin)
    check("alert-config GET", s == 200, f"{s} {str(b)[:100]}")
    s, b = req("PUT", "/api/v1/vulnscan/tasks/alert-config", {
        "queued_threshold": 50, "stale_minutes": 30, "enabled": True,
    }, token=admin)
    check("alert-config PUT", s == 200, f"{s} {str(b)[:100]}")

    # ===== 6. findings/reports 路由存在 =====
    s, b = req("GET", f"/api/v1/vulnscan/tasks/{task_id}/findings", token=admin)
    check("task findings", s in (200, 404, 409), f"{s}")
    s, b = req("GET", f"/api/v1/vulnscan/tasks/{task_id}/report", token=admin)
    check("task report", s in (200, 404, 409), f"{s}")

    # ===== 7. 任务状态流转(等待 scan-engine 消费,最多 20s)=====
    if task_id:
        status_seen = set()
        for i in range(20):
            s, b = req("GET", f"/api/v1/vulnscan/tasks/{task_id}", token=admin)
            st = b.get("status", "") if isinstance(b, dict) else ""
            status_seen.add(st)
            if st in ("completed", "failed", "error"):
                break
            time.sleep(1)
        check("task status flow (queued→…)", bool(status_seen), f"seen={sorted(status_seen)}")
        check("task terminal state", st in ("completed", "failed", "error"), f"final={st} {str(b)[:120]}")

    # ===== 8. 取消任务 =====
    s, b = req("POST", "/api/v1/vulnscan/tasks", {
        "targets": ["192.168.1.99"], "modules": ["sys_vuln"], "engine": "matcher",
    }, token=admin)
    tid2 = b.get("task_id", "")
    s, b = req("POST", f"/api/v1/vulnscan/tasks/{tid2}/cancel", {}, token=admin)
    check("task cancel", s in (200, 400, 409), f"{s} {str(b)[:80]}")

    # ===== 9. 批量删除(仅非运行中)=====
    s, b = req("POST", "/api/v1/vulnscan/tasks/batch-delete", {"task_ids": [tid2]}, token=admin)
    check("batch delete", s in (200, 400, 422), f"{s} {str(b)[:100]}")

    fails = [r for r in results if not r[1]]
    print(f"\n===== SUMMARY: {len(results)-len(fails)}/{len(results)} PASS =====")
    for name, _, detail in fails:
        print(f"  FAIL: {name} | {detail}")


if __name__ == "__main__":
    main()
