import { message } from "antd"

/**
 * 统一错误提示（V10 阶段 3.1 / V12 阶段 3.1）。
 *
 * 全站 ~25 处 `catch { message.error("固定文案") }` 曾各自为政，API 返回的
 * `detail` 被丢弃。这里集中提取 `err.response.data.detail` 并在其为字符串时
 * 展示，否则回退到调用方给的固定文案——未来后端若把错误体改成
 * `{code, message, hint}` 结构，只需改这一个文件。
 */
export function showError(err: unknown, fallback: string): void {
  const anyErr = err as { response?: { data?: { detail?: unknown } } } | null | undefined
  const detail = anyErr?.response?.data?.detail
  const text = typeof detail === "string" && detail ? detail : fallback
  message.error(text)
}
