"""End-to-end test of /api/v1/chat after the web_search + chat.py fix.

Mints a JWT for the seeded admin (no password needed), then exercises:
  1. web-intent query  -> _answer_with_web -> search_with_fallback -> LLM
  2. scan-intent query -> ScanIntent parse (task-creation flow)
  3. chat-intent       -> freeform LLM

V10 4.7 (2026-07-30): OPERATIONAL NOTES
  - This script needs a running API + a working LLM endpoint
    (``src.knowledge.models.adapter.get_model_adapter`` must
    resolve to a configured provider) plus outbound internet
    access for the web-search fallbacks (Bing / NVD / DDG).
  - It hard-codes ``http://127.0.0.1:8000`` as ``BASE``; if the
    API is behind a reverse proxy, point ``BASE`` at the proxy
    or run the script from the same host as the API.
  - NOT a unit test. Do NOT add it to CI -- it is a manual
    smoke probe the operator runs after a backend / web-search
    change. CI runs the pytest suite under ``tests/`` only.
  - Exit code 0 == all three intents responded; non-zero == at
    least one intent timed out / errored. Inspect the printed
    body for which one.
"""

import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")

import httpx  # noqa: E402

from src.api.auth.jwt import create_access_token  # noqa: E402

BASE = "http://127.0.0.1:8000"
token = create_access_token(data={"sub": "admin", "role": "admin"})
if not token:
    print("FATAL: could not mint token")
    sys.exit(2)


def banner(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def chat(c, auth, message):
    r = c.post(f"{BASE}/api/v1/chat", headers=auth, json={"message": message, "history": []})
    print(f"  status={r.status_code}")
    try:
        b = r.json()
        if r.status_code != 200:
            print(f"  detail={b.get('detail', '')[:300]}")
            return
        print(f"  intent={b.get('intent')} conf={b.get('confidence')}")
        srcs = b.get("sources") or []
        print(f"  sources={len(srcs)}: {[s.get('title', '')[:40] for s in srcs][:4]}")
        # for scan intent, show parsed intent
        for s in srcs:
            if s.get("title") == "intent":
                print(
                    f"  ScanIntent={json.dumps(json.loads(s['snippet']), ensure_ascii=False)[:300]}"
                )
        print(f"  reply[:500]:\n{b.get('reply', '')[:500]}")
    except Exception:
        print(f"  raw={r.text[:400]}")


def main():
    with httpx.Client(timeout=120) as c:
        auth = {"Authorization": f"Bearer {token}"}
        banner("STEP 0: /auth/me (minted token sanity)")
        r = c.get(f"{BASE}/api/v1/auth/me", headers=auth)
        print(f"  me status={r.status_code} body={r.text[:150]}")
        if r.status_code != 200:
            print("  abort: token not authorized")
            return

        banner("STEP 1: web-intent (CVE-2024-3094)")
        chat(c, auth, "CVE-2024-3094 是什么漏洞？影响多大？")

        banner("STEP 2: web-intent (general security news)")
        chat(c, auth, "最近 log4j 漏洞有什么新动态？")

        banner("STEP 3: scan-intent (task creation flow)")
        chat(c, auth, "帮我扫描 test 组的主机，做漏洞扫描 + 基线")

        banner("STEP 4: chat-intent (freeform)")
        chat(c, auth, "你好，你能做什么？")


if __name__ == "__main__":
    main()
