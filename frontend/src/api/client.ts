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

// -- Response actions (Phase 4 of monitoring plan) ----------------------
// Dispatch a server-side defensive action (kill_process / quarantine_file)
// to a specific agent. Returns the server-generated action_id so the
// operator can poll for terminal status via getAgentActionStatus.
export interface AgentActionDispatch {
  action_id: string
  action: string
  agent_id: string
  status: string
}
export interface AgentActionStatus {
  action_id: string
  status: string
  detail: string
  agent_id: string
  received_at: string
}
export async function dispatchAgentAction(
  agentId: string,
  actionName: "kill_process" | "quarantine_file",
  params: Record<string, unknown>,
  reason: string,
): Promise<AgentActionDispatch> {
  const res = await api.post(`/agents/${agentId}/actions/${actionName}`, {
    params,
    reason,
  })
  return res.data as AgentActionDispatch
}
export async function getAgentActionStatus(actionId: string): Promise<AgentActionStatus> {
  const res = await api.get(`/agents/actions/${actionId}`)
  return res.data as AgentActionStatus
}

// -- Monitor events (Phase 5 of monitoring plan) -------------------------
// Read the most recent process snapshots uploaded by the agent's
// lightweight monitor. Returns the slim shape (no full process list)
// the server exposes; the full payload lives in ES for forensic drill-down.
export interface MonitorEvent {
  agent_id: string
  hostname: string
  collected_at: string
  received_at: string
  interval_sec: number
  total_count: number
  truncated: boolean
  process_count: number
}
export interface MonitorEventList {
  agent_id: string
  items: MonitorEvent[]
  count: number
  limit: number
}
export async function getAgentMonitor(agentId: string, limit = 20): Promise<MonitorEventList> {
  const res = await api.get(`/agents/${agentId}/monitor`, { params: { limit } })
  return res.data as MonitorEventList
}

// -- Sigma detection rules (Phase 6 of monitoring plan) -----------------
// Read the imported Sigma rules inventory. The console's "妫€娴嬭鍒?
// tab on the Rules page uses these to show the operator what is
// actually loaded into the detector.
export interface SigmaRuleItem {
  path: string
  rule_id: string
  title: string
  level: string
  category: string
  applicable_os: string[]
  detector_supported: boolean
  mitre_techniques: string[]
}
export interface SigmaSummary {
  total_seen: number
  accepted: number
  skipped: number
  by_category: Record<string, number>
  by_os: Record<string, number>
  by_level: Record<string, number>
  skipped_reasons: { path: string; reason: string }[]
  imported_at: string
  rules?: SigmaRuleItem[]
}
export interface SigmaList {
  total: number
  items: SigmaRuleItem[]
}
export async function getSigmaSummary(): Promise<SigmaSummary> {
  const res = await api.get("/sigma-rules/summary")
  return res.data as SigmaSummary
}
export async function getSigmaRules(params: {
  category?: string
  os?: string
  level?: string
  detector_supported?: boolean
  q?: string
} = {}): Promise<SigmaList> {
  const res = await api.get("/sigma-rules", { params })
  return res.data as SigmaList
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

export async function upgradeAgent(agentId: string, version?: string | null) {
  const res = await api.post(`/agents/${agentId}/upgrade`, version ? { version } : {})
  return res.data as {
    status: "ok" | "already_current"
    version: string
    current_version?: string
    delivered: boolean
    binary_path?: string
  }
}

export interface AgentUpgradeStatus {
  agent_id: string
  upgrade: {
    state: string
    target_version?: string
    current_version?: string
    message?: string
    error?: string
    updated_at?: string
  }
}

export async function getAgentUpgradeStatus(agentId: string) {
  const res = await api.get(`/agents/${agentId}/upgrade`)
  return res.data as AgentUpgradeStatus
}

export async function deleteHost(agentId: string, purge: boolean = false) {
  const res = await api.delete(`/agents/${agentId}`, { params: purge ? { purge: true } : undefined })
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
  const res = await api.post("/rules/sync", { source }, { timeout: 300000 })
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

export async function syncNucleiTemplates() {
  const res = await api.post("/rules/sync-nuclei-templates", {}, { timeout: 300000 })
  return res.data as {
    synced: number
    total: number
    version: string
    agents: { agent_id: string; sent: boolean }[]
  }
}

// -- Nuclei 妯℃澘搴?--------------------------------------------------------

export interface NucleiTemplateMeta {
  path: string
  category: string
  template_id: string
  name: string
  severity: string
  tags: string[]
  author: string
  version: string
  content?: string
}

export async function listNucleiTemplates(params?: { category?: string; q?: string; page?: number; page_size?: number }) {
  const res = await api.get("/nuclei-templates", { params })
  return res.data as { items: NucleiTemplateMeta[]; total: number; page: number; size: number; version: string }
}

export async function getNucleiTemplate(path: string) {
  const res = await api.get(`/nuclei-templates/${path}`)
  return res.data as NucleiTemplateMeta
}

export async function saveNucleiTemplate(path: string, content: string) {
  const res = await api.put(`/nuclei-templates/${path}`, { content })
  return res.data as { ok: boolean; path: string; template_id: string; name: string; severity: string }
}

export async function syncNucleiTemplatesLibrary() {
  const res = await api.post("/nuclei-templates/sync", {}, { timeout: 600000 })
  return res.data as { version: string; count: number; indexed: number; es_actual: number; matched: boolean }
}

export async function importNucleiTemplatesZip(file: File) {
  const formData = new FormData()
  formData.append("file", file)
  const res = await api.post("/nuclei-templates/import", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 600000,
  })
  return res.data as { version: string; count: number; upgraded: boolean; previous_version: string }
}

export async function getNucleiTemplatesVersion() {
  const res = await api.get("/nuclei-templates/version")
  return res.data as { version: string }
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

/**
 * Structured scan intent returned by the LLM and persisted on the assistant
 * turn (see ChatMessage.intent). Mirrors ScanIntent on the backend; keep
 * the field names in sync with src/agents/models.py.
 */
export interface ScanIntentData {
  targets: string[]
  modules: string[]
  engine?: string
  resource_limit?: Record<string, unknown>
  schedule?: string | null
  // nuclei-specific knobs (only used when engine === 'nuclei')
  nuclei_severity?: string[]
  nuclei_tags?: string[]
  nuclei_templates?: string[]
  nuclei_timeout_sec?: number
}


export interface ChatMessage {
  role: "user" | "assistant" | "system"
  content: string
  ts?: string
  // Persisted per-message metadata (backend whitelists: route, intent,
  // sources, task_id). Used so historical intent cards re-render without
  // a second LLM call and to surface the created task_id as a link.
  route?: ChatRoute
  intent?: ScanIntentData
  sources?: ChatSource[]
  task_id?: string
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

/**
 * Write back per-message metadata (e.g. the task_id produced by clicking
 * "执行扫描"). Lets the historical intent card show "已创建任务 #xxx → 查看"
 * instead of the original executable button on reload.
 */
export async function patchMessage(
  conversationId: string,
  ts: string,
  patch: { task_id?: string },
): Promise<Conversation> {
  const res = await api.patch(
    `/vulnscan/conversations/${conversationId}/messages/${encodeURIComponent(ts)}`,
    patch,
  )
  return res.data as Conversation
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
  // The PG-persisted `ts` of the assistant turn we just wrote. The
  // frontend adopts this verbatim so the in-memory `ts` matches what
  // lives in the conversation store -- a later
  // `patchMessage(task_id)` is then guaranteed to find the same
  // row by `ts` (otherwise microsecond / timezone drift causes the
  // patch to silently miss).
  assistant_ts?: string
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
  // V12 5.9 (2026-08-02): the axios default is 30s, but LLM-generated
  // answers ("详细介绍某主机漏洞情况") routinely take longer -- a long
  // answer times out client-side as "timeout of 30000ms exceeded".
  // Override per-request to 120s, matching server llm_request_timeout_sec.
  const res = await api.post("/chat", {
    message,
    history,
    model_id: modelId ?? null,
    conversation_id: conversationId,
  }, { timeout: 120000 })
  const body = res.data as ChatAssistantResponse
  // F2 (2026-07-29): the unified /chat router now persists the user +
  // assistant turn itself (via the conversation store), so the reply we
  // render here is exactly what is stored -- no second LLM call and no
  // divergent persisted reply. We trust the /chat response as the single
  // source of truth.
  return body
}

// -- Scan tasks -----------------------------------------------------------

// Scan engine options. "global" runs the internal matcher AND nuclei on
// each target in a single task so the operator only waits once.
export type ScanEngine = "matcher" | "nuclei" | "global"

export interface CreateScanTaskRequest {
  source: string
  intent_text?: string
  targets: string[]
  modules?: string[]
  engine?: ScanEngine
  nuclei_severity?: string[]
  nuclei_tags?: string[]
  nuclei_templates?: string[]
  nuclei_timeout_sec?: number
  // Empty / unset = scan every listening TCP port on the host (resolved
  // via ss -tlnpH on the agent). Populated when the operator wants to
  // limit the nuclei scan to a specific port list (e.g. 80,443,8000).
  nuclei_ports?: number[]
}

export async function createScanTask(req: CreateScanTaskRequest, sync = false) {
  // sync=true bypasses the Redis Stream queue and runs the subgraph inline
  // inside the request -- safer when the TaskWorker is offline, slower on
  // big targets because the HTTP connection blocks until done. Default
  // false keeps the existing async (P2) behavior.
  const res = await api.post("/vulnscan/tasks", req, { params: sync ? { sync: 1 } : undefined })
  return res.data as { task_id: string; status: string; engine: string }
}

export async function cancelScanTask(taskId: string) {
  const res = await api.post(`/vulnscan/tasks/${taskId}/cancel`)
  return res.data as { status: string; sent: number; failed: number }
}

export async function deleteScanTask(taskId: string) {
  const res = await api.delete(`/vulnscan/tasks/${taskId}`)
  return res.data
}

export async function batchDeleteScanTasks(taskIds: string[]) {
  const res = await api.post("/vulnscan/tasks/batch-delete", { task_ids: taskIds })
  return res.data as { deleted: number; not_found: string[]; failed: string[] }
}

export async function listScanTasks() {
  const res = await api.get("/vulnscan/tasks")
  return res.data as { items: any[] }
}

// ---- Host groups (stubs for pre-existing pages) ----
export interface HostGroup {
  name: string
  description: string | null
  member_count: number
  origin?: "managed" | "legacy"
}

export async function listHosts(params?: {
  group?: string
  status?: string
  include_decommissioned?: boolean
}) {
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
  const res = await api.get("/agents/install", { params: { token, os } })
  return (res.data as any)?.script ?? (res.data as unknown as string)
}

export async function getInstallHelper(token: string, os: "linux" | "windows" = "linux") {
  const res = await api.get("/agents/install-helper", { params: { token, os } })
  return (res.data as any)?.helper ?? (res.data as unknown as string)
}

// -- User management ------------------------------------------------------
export type UserRole = "admin" | "analyst" | "viewer" | "responder"
export interface ManagedUser {
  username: string
  role: UserRole
  disabled: boolean
  created_at: string | null
  updated_at: string | null
  last_login_at: string | null
  deleted_at: string | null
}
export async function listUsers(includeDeleted = false) {
  const res = await api.get("/users", { params: { include_deleted: includeDeleted } })
  return res.data as { items: ManagedUser[]; count: number }
}
export async function createUser(data: { username: string; password: string; role: UserRole }) {
  const res = await api.post("/users", data)
  return res.data as ManagedUser
}
export async function updateUser(username: string, data: { username?: string; role?: UserRole; disabled?: boolean }) {
  const res = await api.patch(`/users/${encodeURIComponent(username)}`, data)
  return res.data as ManagedUser
}
export async function deleteUser(username: string) {
  const res = await api.delete(`/users/${encodeURIComponent(username)}`)
  return res.data as { status: string }
}
export async function restoreUser(username: string) {
  const res = await api.post(`/users/${encodeURIComponent(username)}/restore`)
  return res.data as ManagedUser
}
export async function changePassword(oldPassword: string, newPassword: string) {
  const res = await api.post("/users/me/password", { old_password: oldPassword, new_password: newPassword })
  return res.data as { status: string }
}


// -- Vuln scan results (2026-07-29 UX upgrade) -------------------------------
export interface VulnFinding {
  finding_id: string
  task_id: string
  agent_id: string
  hostname: string
  category: string
  cve: string | null
  name: string
  severity: string
  ai_severity: string | null
  ai_filtered: boolean
  evidence: string
  fix_advice: string | null
  status: "open" | "fixed" | "accepted"
  detected_at: string
  // Prior-scan detection times (consolidation 2026-07-31); detected_at is the latest.
  scan_history?: string[]
  // AI evidence (optional; old docs may not have them)
  ai_processed?: boolean
  ai_reason?: string | null
  ai_fix_summary?: string | null
  ai_processed_at?: string
  first_fixed_at?: string | null
  last_fixed_at?: string | null
}

export interface VulnFilter {
  task_id?: string
  hostname?: string
  severity?: string
  status?: string
  cve?: string
  cve_keyword?: string
  hostname_keyword?: string
  name_keyword?: string
  group?: string
  ai_processed?: boolean
  date_from?: string
  date_to?: string
}

export async function listVulns(filter: VulnFilter = {}) {
  // Drop undefined/null/empty params so the URL stays clean.
  const params: Record<string, string> = {}
  for (const [k, v] of Object.entries(filter)) {
    if (v === undefined || v === null || v === "") continue
    params[k] = String(v)
  }
  const res = await api.get("/vulnscan/results", { params })
  return res.data as { items: VulnFinding[] }
}

export async function getVuln(findingId: string) {
  const res = await api.get(`/vulnscan/vulns/${encodeURIComponent(findingId)}`)
  // 2026-07-29 UX upgrade: backend now attaches the host meta as a
  // sibling field on the vuln detail. Old responses (pre-upgrade)
  // simply lack the field, so we keep it optional.
  return res.data as VulnFinding & { host?: Host }
}

export interface ScanReport {
  task_id: string
  summary: string
  ai_analysis: string
  stats: { by_severity: Record<string, number>; by_category: Record<string, number>; total: number; filtered_out: number }
  top_vulns: Array<{ hostname: string; name: string; cve: string | null; severity: string; ai_severity?: string; fix_advice?: string | null }>
  recommendations: string[]
  generated_at: string
  ai_processed?: boolean
  ai_model?: string
  ai_overall_advice?: string
  ai_processed_at?: string
}

export async function getReport(taskId: string) {
  const res = await api.get(`/vulnscan/reports/${encodeURIComponent(taskId)}`)
  return res.data as ScanReport
}

export async function patchVulnStatus(findingId: string, status: VulnFinding["status"]) {
  const res = await api.patch(`/vulnscan/vulns/${encodeURIComponent(findingId)}`, { status })
  return res.data as { status: string }
}

export interface HostStatsRow {
  group: string
  member_count: number
  total: number
  by_severity: Record<string, number>
}

export async function getHostStats() {
  const res = await api.get("/vulnscan/host-stats")
  return res.data as { items: HostStatsRow[] }
}
