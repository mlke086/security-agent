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
      command: `"${PY}" -m uvicorn src.api.main:app --port ${API_PORT}`,
      cwd: '..',
      port: API_PORT,
      timeout: 60_000,
      reuseExistingServer: false,
      env: {
        ...process.env,
        API_SECRET_KEY: 'e2e-secret-key-0000000',
        STORE_BACKEND: 'memory',
        HITL_TIMEOUT_SEC: '5',
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
