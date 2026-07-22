import axios from "axios"
import type { EventRecord, Approval, Metrics, TimelinePoint } from "../types"

// same-origin default; can override via VITE_API_BASE_URL at build time.
const host = window.location.hostname
const proto = window.location.protocol
const port = window.location.port
const apiBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)
  || ((host === "localhost" || host === "127.0.0.1")
       ? "/api/v1"
       : `${proto}//${host}${port ? ":" + port : ""}/api/v1`)

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
      if (!err.config?.url?.includes("/auth/login")) {
        window.location.href = "/login"
      }
    }
    return Promise.reject(err)
  },
)

export type SseScope = "events" | "events_list" | "metrics" | "approval"

export async function getSseToken(scope: SseScope): Promise<string> {
    const res = await api.post("/auth/sse-token", { scope })
    return (res.data as { token: string }).token
}

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
  const res = await api.get("/agents/console-url")
  return (res.data as { url: string }).url
}

export async function getAgents() {
  const res = await api.get("/agents")
  return res.data as { items: Host[] }
}

export async function deleteHost(agentId: string, _force?: boolean) {
  const res = await api.delete(`/agents/${agentId}`)
  return res.data
}

export async function updateHostGroup(agentId: string, group: string | null) {
  const res = await api.patch(`/agents/${agentId}`, { group })
  return res.data as { status: string }
}

// -- Rules ----------------------------------------------------------------

export interface RuleItem {
  id: string
  category: string
  cve: string | null
  name: string
  severity: string
  check: {
    type: string
    name?: string
    op?: string
    value?: string
    file?: string
    pattern?: string
    expect?: string
  }
  fix: string
}

export async function listRules(params?: { category?: string; severity?: string; q?: string; page?: number; page_size?: number }) {
  const res = await api.get("/rules/list", { params })
  return res.data as { version: string; total: number; page: number; page_size: number; items: RuleItem[] }
}

export async function getRuleVersion() {
  const res = await api.get("/rules/version")
  return res.data as { version: string }
}

export async function syncRules(source: string = "nvd") {
  const res = await api.post("/rules/sync", { source })
  return res.data as { version: string; count: number }
}

export async function importRules(file: File) {
  const formData = new FormData()
  formData.append("file", file)
  const res = await api.post("/rules/import", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  })
  return res.data as { version: string; count: number }
}

export async function syncRulesToAgents() {
  const res = await api.post("/rules/sync-to-agents")
  return res.data as { synced: number; total: number; agents: { agent_id: string; sent: boolean }[] }
}

// -- LLM Models -----------------------------------------------------------

export interface LlmModel {
  id: number
  name: string
  provider: string
  model_name: string
  has_key: boolean
  base_url: string
  temperature: number
  max_tokens: number
  supports_structured: boolean
  enabled: boolean
  is_default: boolean
}

export type ModelSubmit = Omit<LlmModel, "id" | "has_key"> & {
  api_key?: string
}

export async function listModels() {
  const res = await api.get("/models")
  return res.data as { items: LlmModel[] }
}

export async function createModel(data: ModelSubmit) {
  const res = await api.post("/models", data)
  return res.data as LlmModel
}

export async function updateModel(id: number, data: ModelSubmit) {
  const res = await api.patch(`/models/${id}`, data)
  return res.data as LlmModel
}

export async function deleteModel(id: number) {
  const res = await api.delete(`/models/${id}`)
  return res.data
}

export async function setDefaultModel(id: number) {
  const res = await api.post(`/models/${id}/default`)
  return res.data as LlmModel
}

export async function testModel(id: number) {
  const res = await api.post(`/models/${id}/test`)
  return res.data as { ok: boolean; reply?: string; error?: string }
}

// -- Scan conversations (legacy scan-intent flow) -------------------------

export interface ChatMessage {
  role: "user" | "assistant" | "system"
  content: string
  ts?: string
}

export interface Conversation {
  id: string
  title: string
  model_id: number | null
  messages: ChatMessage[]
  created_at: string
  updated_at: string
}

export interface ConversationSummary {
  id: string
  title: string
  model_id: number | null
  created_at: string
  updated_at: string
}

export async function listConversations() {
  const res = await api.get("/vulnscan/conversations")
  return res.data as { items: ConversationSummary[] }
}

export async function createConversation(title?: string, modelId?: number | null) {
  const res = await api.post("/vulnscan/conversations", { title, model_id: modelId ?? null })
  return res.data as Conversation
}

export async function getConversation(id: string) {
  const res = await api.get(`/vulnscan/conversations/${id}`)
  return res.data as Conversation
}

export async function updateConversation(id: string, data: { title?: string; model_id?: number | null }) {
  const res = await api.patch(`/vulnscan/conversations/${id}`, data)
  return res.data as Conversation
}

export async function deleteConversation(id: string) {
  const res = await api.delete(`/vulnscan/conversations/${id}`)
  return res.data
}

export async function chatConversation(id: string, message: string, modelId?: number | null, parseIntent?: boolean) {
  const res = await api.post(`/vulnscan/conversations/${id}/chat`, {
    message,
    model_id: modelId ?? null,
    parse_intent: parseIntent ?? false,
  })
  return res.data as { reply: string; intent?: any; conversation: Conversation }
}

// -- General assistant (project Q&A + web search + scan routing) ----------

export type ChatRoute = "scan" | "project" | "web" | "chat"

export interface ChatSource {
  title: string
  url?: string | null
  snippet?: string
}

export interface ChatAssistantResponse {
  intent: ChatRoute
  confidence: number
  reply: string
  sources: ChatSource[]
}

/**
 * Unified chat entrypoint. Sends the user's message along with prior turns
 * (sliced from the loaded conversation) so the backend router has full
 * context. The backend returns the chosen route + reply + any retrieved
 * sources. Persisting the message to the conversation history happens
 * server-side in the scan_chat path; here we only persist via the same
 * /vulnscan/conversations/{id}/chat endpoint after a successful response.
 */
export async function chatAssistant(
  conversationId: string,
  message: string,
  modelId?: number | null,
): Promise<ChatAssistantResponse> {
  // Step 1: fetch conversation so we have the recent turns (limit to last
  // 12 to keep the prompt small).
  const conv = await getConversation(conversationId)
  const history = (conv.messages || []).slice(-12).map((m) => ({
    role: m.role as "user" | "assistant",
    content: m.content,
  }))
  // Step 2: call the unified router.
  const res = await api.post("/chat", {
    message,
    history,
    model_id: modelId ?? null,
    conversation_id: conversationId,
  })
  const body = res.data as ChatAssistantResponse
  // Step 3: persist this turn into the scan conversation history so the
  // sidebar list / refresh keeps showing context.
  try {
    await chatConversation(conversationId, message, modelId, false)
  } catch {
    // best-effort -- the unified chat response is the source of truth
  }
  return body
}

// -- Scan tasks -----------------------------------------------------------

export interface CreateScanTaskRequest {
  source: string
  intent_text?: string
  targets: string[]
  modules?: string[]
  engine?: string
  nuclei_severity?: string[]
  nuclei_tags?: string[]
  nuclei_templates?: string[]
  nuclei_timeout_sec?: number
}

export async function createScanTask(req: CreateScanTaskRequest) {
  const res = await api.post("/vulnscan/tasks", req)
  return res.data as { task_id: string; status: string; engine: string }
}

export async function deleteScanTask(taskId: string) {
  const res = await api.delete(`/vulnscan/tasks/${taskId}`)
  return res.data
}

export async function listScanTasks() {
  const res = await api.get("/vulnscan/tasks")
  return res.data as { items: any[] }
}

// ── Host groups (stubs for pre-existing pages) ───────────────────────
export interface HostGroup {
  name: string
  description: string | null
  member_count: number
  origin?: "managed" | "legacy"
}

export async function listHosts(params?: { group?: string; status?: string }) {
  const res = await api.get("/agents", { params })
  return res.data as { items: Host[] }
}

export async function listGroups() {
  const res = await api.get("/agents/groups")
  return res.data as { items: HostGroup[] }
}

export async function createGroup(name: string, description?: string) {
  const res = await api.post("/agents/groups", { name, description: description ?? null })
  return res.data as HostGroup
}

export async function deleteGroup(name: string) {
  const res = await api.delete(`/agents/groups/${encodeURIComponent(name)}`)
  return res.data
}

export async function getInstallScript(token: string, os: "linux" | "windows" = "linux") {
  const res = await api.get("/agents/install-script", { params: { token, os } })
  return (res.data as any)?.script ?? (res.data as unknown as string)
}

export async function getInstallHelper(token: string, os: "linux" | "windows" = "linux") {
  const res = await api.get("/agents/install-helper", { params: { token, os } })
  return (res.data as any)?.helper ?? (res.data as unknown as string)
}
