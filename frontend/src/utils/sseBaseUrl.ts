import api from "../api/client"

/**
 * SSE base URL（V10 阶段 3.5 / V12 阶段 3.3）。
 *
 * DashboardPage / EventQueuePage / EventDetailPage / ScanMonitorPage 曾各自
 * 拼接 ``api.defaults.baseURL`` 并 strip 尾斜杠。SSE 用短时 token（非 JWT）
 * 拼进 URL，四个页面行为必须一致——集中一处，避免某页改漏导致
 * 404/连接失败。
 */
export function sseBaseUrl(): string {
  return (api.defaults.baseURL || "").replace(/\/+$/, "")
}
