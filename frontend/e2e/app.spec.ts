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
