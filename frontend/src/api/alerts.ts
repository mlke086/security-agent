/**Alerts API client (Phase 2 of monitoring plan).

Mirrors the backend's POST/GET/PATCH endpoints under
/api/v1/alerts. Kept in a separate file so the alerts page can
lazy-import only this and the existing types module.
*/
import api from "./client"

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info"
export type AlertStatus =
  | "new"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "false_positive"
export type AlertSource =
  | "wazuh"
  | "elkeid"
  | "syslog"
  | "elastic"
  | "crowdstrike"
  | "sentinelone"
  | "secagent"
  | "unknown"

export interface AlertIOC {
  ips: string[]
  domains: string[]
  hashes: string[]
  urls: string[]
  emails: string[]
  users: string[]
}

export interface AlertRecord {
  alert_id: string
  source: AlertSource | string
  title: string
  description?: string
  severity: AlertSeverity | string
  status: AlertStatus | string
  occurred_at: string
  received_at: string
  hostname?: string
  host_ip?: string
  agent_id?: string
  rule_id?: string
  rule_name?: string
  category?: string
  mitre_attack?: string[]
  iocs?: AlertIOC
  tags?: string[]
  source_url?: string
  raw?: Record<string, unknown>
}

export interface ListAlertsParams {
  severity?: AlertSeverity
  status?: AlertStatus
  source?: AlertSource
  hostname?: string
  limit?: number
  offset?: number
}

export interface ListAlertsResponse {
  items: AlertRecord[]
  limit: number
  offset: number
  count: number
}

export async function listAlerts(params: ListAlertsParams = {}): Promise<ListAlertsResponse> {
  const cleaned: Record<string, string | number> = {}
  if (params.severity) cleaned.severity = params.severity
  if (params.status) cleaned.status = params.status
  if (params.source) cleaned.source = params.source
  if (params.hostname) cleaned.hostname = params.hostname
  if (params.limit !== undefined) cleaned.limit = params.limit
  if (params.offset !== undefined) cleaned.offset = params.offset
  const res = await api.get("/alerts", { params: cleaned })
  return res.data as ListAlertsResponse
}

export async function getAlert(alertId: string): Promise<AlertRecord> {
  const res = await api.get(`/alerts/${encodeURIComponent(alertId)}`)
  return res.data as AlertRecord
}

export async function ingestAlert(
  source: AlertSource,
  payload: Record<string, unknown>
): Promise<{ alert_id: string; received_at: string; severity: AlertSeverity }> {
  const res = await api.post("/alerts/ingest", { source, payload })
  return res.data
}

export async function updateAlertStatus(
  alertId: string,
  status: AlertStatus
): Promise<{ alert_id: string; status: AlertStatus; updated_at: string }> {
  const res = await api.patch(
    `/alerts/${encodeURIComponent(alertId)}/status`,
    { status }
  )
  return res.data
}