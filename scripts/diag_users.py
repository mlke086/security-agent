"""检查 users 表 admin 用户 + admin123 密码是否有效。"""
import asyncio

import asyncpg
from passlib.context import CryptContext


async def main() -> None:
    conn = await asyncpg.connect(
        host="192.168.80.101", port=5432, user="secagent", password="Ke615700", database="SecAgent"
    )
    try:
        rows = await conn.fetch(
            "SELECT username, role, disabled, hashed_password FROM users ORDER BY username LIMIT 10"
        )
        print(f"users: {len(rows)}")
        for r in rows:
            print(f" - {r['username']} role={r['role']} disabled={r['disabled']}")
        pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        admin = next((r for r in rows if r["username"] == "admin"), None)
        if admin:
            ok = pwd_ctx.verify("admin123", admin["hashed_password"])
            print("admin/admin123 verify:", ok)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
