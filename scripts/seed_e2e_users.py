"""前端 e2e 前置:把 PG 测试用户重置为 e2e 用例硬编码的密码。

Playwright webServer 直接起 uvicorn(不经 pytest/conftest),而 PG 中
admin 等用户的密码可能已被生产/其他测试轮换,导致 e2e 的 admin/admin123
登录 401。本脚本在启动后端前执行,复用 conftest 的 _seed_test_users
(UPSERT,幂等),保证 admin123 / analyst123 / viewer123 / responder123 可用。
"""
import asyncio
import os
import sys

os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("PG_PORT", "5432")
os.environ.setdefault("PG_DATABASE", "SecAgent")
os.environ.setdefault("PG_USER", "secagent")
os.environ.setdefault("PG_PASSWORD", "Ke615700")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


async def main() -> None:
    from src.common.db.pg import get_pg_pool

    import bcrypt

    pool = await get_pg_pool()
    try:
        test_users = [
            ("admin", "admin123", "admin"),
            ("analyst", "analyst123", "analyst"),
            ("viewer", "viewer123", "viewer"),
            ("responder", "responder123", "responder"),
        ]
        async with pool.acquire() as conn:
            for username, password, role in test_users:
                # bcrypt 直接哈希($2b$ 前缀,与 passlib CryptContext 互认)
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
                await conn.execute(
                    """
                    INSERT INTO users (username, hashed_password, role, disabled, created_at, updated_at)
                    VALUES ($1, $2, $3, FALSE, NOW(), NOW())
                    ON CONFLICT (username)
                    DO UPDATE SET hashed_password = EXCLUDED.hashed_password,
                                  role = EXCLUDED.role,
                                  disabled = FALSE,
                                  deleted_at = NULL,
                                  updated_at = NOW()
                    """,
                    username,
                    hashed,
                    role,
                )
        print(f"e2e users seeded: {[u[0] for u in test_users]}")
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
