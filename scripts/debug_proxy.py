"""阶段 3-4 调试:gateway 反代到 ai /api/v1/chat 时到底发生了什么。"""
import asyncio
import os
import sys
sys.path.insert(0, "src")

import httpx


async def main():
    base = "http://127.0.0.1:18001"
    payload = {"text": "hi"}

    async with httpx.AsyncClient(timeout=10) as client:
        # 1. 直连 ai
        try:
            r = await client.post(f"{base}/api/v1/chat", json=payload)
            print(f"[ai direct] status={r.status_code} body={r.text[:200]}")
        except Exception as e:
            print(f"[ai direct] EXC {type(e).__name__}: {e}")

        # 2. 经 gateway 反代
        try:
            r = await client.post("http://127.0.0.1:18000/api/v1/chat", json=payload)
            print(f"[gateway proxy] status={r.status_code} body={r.text[:200]}")
            print(f"[gateway proxy] headers={dict(r.headers)}")
        except Exception as e:
            print(f"[gateway proxy] EXC {type(e).__name__}: {e}")

        # 3. gateway /health
        try:
            r = await client.get("http://127.0.0.1:18000/health")
            print(f"[gateway /health] status={r.status_code} body={r.text[:200]}")
        except Exception as e:
            print(f"[gateway /health] EXC {type(e).__name__}: {e}")


asyncio.run(main())