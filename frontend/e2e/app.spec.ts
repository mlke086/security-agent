import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page, username = 'admin', password = 'admin123') {
  await page.goto('/login')
  await page.getByPlaceholder('用户名').fill(username)
  await page.getByPlaceholder('密码').fill(password)
  await page.getByRole('button', { name: /登\s*录/ }).click()
}

test('login succeeds and shows the dashboard', async ({ page }) => {
  await login(page)
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByText('态势感知')).toBeVisible()
})

test('login fails with the wrong password', async ({ page }) => {
  await login(page, 'admin', 'wrong')
  await expect(page.getByText('用户名或密码错误')).toBeVisible()
})

test('dashboard renders stat cards and charts', async ({ page }) => {
  await login(page)
  await expect(page.getByText('总事件数')).toBeVisible()
  await expect(page.getByText('结论分布')).toBeVisible()
  await expect(page.getByText('事件趋势（按小时）')).toBeVisible()
})

// 2026-08-06 更新:原用例依赖已移除的"注入演示数据"按钮,改为验证
// 事件队列页面导航(菜单项"事件队列"仍在)。
test('admin can navigate to the event queue', async ({ page }) => {
  await login(page)
  await page.getByRole('menuitem', { name: /事件队列/ }).click()
  await expect(page).toHaveURL(/\/events/)
})

// V12 阶段 4.3: nuclei 模板库 tab（需要后端 + ES 在线时执行）
test('rules page shows the nuclei templates tab', async ({ page }) => {
  await login(page)
  await page.getByRole('menuitem', { name: /规则/ }).click()
  await expect(page).toHaveURL(/\/rules/)
  // 「同步 Nuclei 模板」按钮存在（V11 新增）
  await expect(page.getByRole('button', { name: /同步 Nuclei 模板/ })).toBeVisible()
})

// 2026-08-06 更新:原 /扫描/ 正则同时命中"扫描任务"与"扫描报告"(strict mode
// violation),改为精确匹配"扫描任务"菜单项。
test('scan tasks page is reachable', async ({ page }) => {
  await login(page)
  await page.getByRole('menuitem', { name: '扫描任务' }).click()
  await expect(page).toHaveURL(/\/scan$/)
})
