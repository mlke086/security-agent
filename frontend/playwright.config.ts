import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

// Resolve the venv python relative to this config (frontend/) so it works
// regardless of the shell's cwd handling on Windows.
const PY = path.resolve(process.cwd(), '..', '.venv', 'Scripts', 'python.exe')
const API_PORT = 8010

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  timeout: 40_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  // Auto-start the backend (uvicorn, STORE_BACKEND=memory keeps E2E off ES) and
  // the frontend dev server. The vite proxy is pointed at the backend via
  // E2E_API_TARGET so dev (default :8000) and E2E (:8010) don't collide.
  webServer: [
    {
      // 阶段 5 测试修复(2026-08-06):e2e 后端必须能连 PG 才能登录——
      // 1) 先跑 seed_e2e_users.py 把测试用户重置为 admin123/analyst123/...;
      //    直接起 uvicorn 不经 pytest/conftest,PG 中 admin 密码可能已被
      //    轮换导致 e2e 的 admin/admin123 登录 401(实测根因)。
      // 2) 再以相同 env 启动后端(含 PG_PASSWORD)。
      command: `"${PY}" scripts/seed_e2e_users.py && "${PY}" -m uvicorn src.api.main:app --port ${API_PORT}`,
      cwd: '..',
      port: API_PORT,
      timeout: 60_000,
      reuseExistingServer: false,
      env: {
        ...process.env,
        API_SECRET_KEY: 'e2e-secret-key-0000000',
        STORE_BACKEND: 'memory',
        HITL_TIMEOUT_SEC: '5',
        PG_HOST: '192.168.80.101',
        PG_PORT: '5432',
        PG_DATABASE: 'SecAgent',
        PG_USER: 'secagent',
        PG_PASSWORD: 'Ke615700',
      } as Record<string, string>,
    },
    {
      command: 'npm run dev',
      cwd: '.',
      port: 3000,
      timeout: 60_000,
      reuseExistingServer: false,
      env: {
        ...process.env,
        E2E_API_TARGET: `http://127.0.0.1:${API_PORT}`,
      } as Record<string, string>,
    },
  ],
})
