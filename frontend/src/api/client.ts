import axios from 'axios'
import type { EventRecord, Approval, Metrics, TimelinePoint } from '../types'

const host = window.location.hostname
const apiBase = (host === "localhost" || host === "127.0.0.1")
  ? "/api/v1"
  : `http://${host}:8000/api/v1`

const api = axios.create({
  baseURL: apiBase,
  timeout: 30000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token")
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token"); localStorage.removeItem("role")
      // Don't hard-reload on the login endpoint itself (wrong credentials);
      // let the login form show the error toast instead of wiping it on reload.
      if (!err.config?.url?.includes("/auth/login")) {
        window.location.href = "/login"
      }
    }
    return Promise.reject(err)
  },
)

export default api

export async function login(username: string, password: string) {
  const res = await api.post("/auth/login", { username, password })
  return res.data
}

export async function submitEvent(sanitizedText: string, iocs: Record<string, string[]>, source: string, sync = false) {
  const res = await api.post("/events", { sanitized_text: sanitizedText, iocs, source }, { params: { sync } })
  return res.data
}

export async function getEvents(params?: { status?: string; verdict?: string; priority?: string; limit?: number; offset?: number }) {
  const res = await api.get("/events", { params })
  return res.data as { items: EventRecord[]; total: number }
}

export async function getEventDetail(eventId: string) {
  const res = await api.get(`/events/${eventId}`)
  return res.data as EventRecord
}

export async function getEventTrace(eventId: string) {
  const res = await api.get(`/events/${eventId}/trace`)
  return res.data
}

export async function approveEvent(eventId: string, action: string, note = "") {
  const res = await api.post(`/events/${eventId}/approve`, null, { params: { action, note } })
  return res.data
}

export async function getApprovals() {
  const res = await api.get("/approvals")
  return res.data as { items: Approval[] }
}

export async function getMetrics() {
  const res = await api.get("/metrics")
  return res.data as Metrics
}

export async function getMetricsTimeline() {
  const res = await api.get("/metrics/timeline")
  return res.data as { timeline: TimelinePoint[] }
}

export async function seedDemo() {
  const res = await api.post("/demo/seed")
  return res.data
}

export async function getMe() {
  const res = await api.get("/auth/me")
  return res.data
}
// -- Agent / Vulnscan APIs ------------------------------------------------

export interface Host {
  agent_id: string; hostname: string; ip: string; os: string; arch: string; kernel: string;
  status: string; agent_version: string; rule_version: string; last_heartbeat: string;
  group: string | null; owner: string | null; env: string | null; created_at: string;
}

export interface EnrollTokenResponse { token: string; expires: string }
export interface EnrollResponse { agent_id: string; agent_token: string; ws_url: string; heartbeat_interval: number }

export async function createEnrollToken(group: string | null, ttl_hours: number, uses: number) {
  const res = await api.post("/agents/enroll-tokens", { group, ttl_hours, uses })
  return res.data as EnrollTokenResponse
}

export async function getConsoleUrl(): Promise<string> {
  // Ask the backend for the canonical console URL it should be embedded with.
  // Prefer this over `window.location.origin` because the operator may have
  // hit the console through a reverse proxy / k8s ingress / different port,
  // while the install script on the target host needs the deployable URL.
  try {
    const res = await api.get("/agents/console-url")
    return (res.data?.console_url as string) || window.location.origin
  } catch {
    return window.location.origin
  }
}

export async function getInstallHelper(token: string, os: string) {
  const res = await api.get("/agents/install-helper", { params: { token, os }, responseType: "text" })
  return res.data
}

export async function getInstallScript(token: string, os: string) {
  const res = await api.get("/agents/install", { params: { token, os }, responseType: "text" })
  return res.data as string
}

export async function listHosts(params?: { status?: string; group?: string }) {
  const res = await api.get("/agents", { params })
  return res.data as { items: Host[] }
}

export async function getHostDetail(agentId: string) {
  const res = await api.get(`/agents/${agentId}`)
  return res.data as Host
}

export async function deleteHost(agentId: string) {
  const res = await api.delete(`/agents/${agentId}`)
  return res.data
}
