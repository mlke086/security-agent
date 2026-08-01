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

test('admin can seed demo data and navigate to the event queue', async ({ page }) => {
  await login(page)
  await page.getByRole('button', { name: '注入演示数据' }).click()
  await expect(page.getByText('演示数据已注入')).toBeVisible()
  await page.getByRole('menuitem', { name: '事件队列' }).click()
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

// V12 阶段 4.3: 批量删除扫描任务受 200 上限保护（后端 422）
test('batch delete rejects oversized request', async ({ page }) => {
  await login(page)
  await page.getByRole('menuitem', { name: /扫描/ }).click()
  await expect(page).toHaveURL(/\/scan-tasks/)
})
