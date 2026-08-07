import { useEffect, useRef, useState, useMemo, useCallback } from "react"
import {
  Input, Button, Select, message, List, Popconfirm, Tooltip, Tag,
} from "antd"
import {
  SendOutlined, PlusOutlined, ThunderboltOutlined, DeleteOutlined,
  RobotOutlined, UserOutlined, MessageOutlined,
  BulbOutlined, ScanOutlined, GlobalOutlined,
} from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import {
  listConversations, createConversation, getConversation, deleteConversation,
  updateConversation, listModels,
  chatAssistant, createScanTask, listGroups, listHosts, type Host, type HostGroup,
  type ConversationSummary, type ChatMessage, type LlmModel,
  type ChatRoute, type ChatSource, type ScanIntentData,
  patchMessage,
} from "../api/client"
import Markdown from "./Markdown"
import "./Markdown.css"
import "./ChatScan.css"

/**
 * ChatScan - 豆包风格对话助手（扫描 + 项目问答 + 联网搜索）
 *
 * 关键设计：
 *   - 单一对话流：聊天记录存到 scan_conversations（沿用现有存储）
 *   - 消息路由：每条用户消息先调 /chat 端点（带历史上下文），由后端 LLM
 *     路由到 scan / project / web / chat 四类之一
 *   - 扫描意图：路由命中 scan 时，后端返回结构化 ScanIntent + 展示卡片
 *     点「执行扫描」才真正 POST /vulnscan/tasks 创建任务
 *   - 项目问答：路由命中 project 时，从 docs/ 检索 + LLM 总结，附文件源
 *   - 联网搜索：路由命中 web 时，DDG HTML 搜索 + LLM 总结，附 URL 源
 */

interface ChatMessageEx extends ChatMessage {
  /** 后端返回的路由分类（assistant 消息才有） */
  route?: ChatRoute
  /** 引用的来源（project docs / web URLs） */
  sources?: ChatSource[]
  /** 解析出的扫描意图（仅 scan 路由） */
  intent?: ScanIntentData
  /** 是否正在等待流式响应 */
  pending?: boolean
  /** 失败时的错误提示 */
  error?: string
}

interface NucleiOptions {
  nuclei_ports: number[]
  nuclei_severity: string[]
  nuclei_tags: string[]
  nuclei_templates: string
  nuclei_timeout_sec: number
}

const ROUTE_LABEL: Record<ChatRoute, { text: string; cls: string }> = {
  scan:    { text: "🔍 扫描意图识别", cls: "scan" },
  system:  { text: "🔧 系统能力", cls: "system" },
  chat:    { text: "💬 自由对话", cls: "chat" },
}

const MODULE_NAME: Record<string, string> = {
  sys_vuln: "系统漏洞",
  baseline: "安全基线",
}

export default function ChatScan() {
  const navigate = useNavigate()
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessageEx[]>([])
  const [input, setInput] = useState("")
  const [sending, setSending] = useState(false)
  const [loadingConv, setLoadingConv] = useState(false)
  const [models, setModels] = useState<LlmModel[]>([])
  const [modelId, setModelId] = useState<number | null>(null)
  const [executing, setExecuting] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // load conversations + models
  useEffect(() => {
    listConversations().then((r) => setConversations(r.items || [])).catch(() => {})
    listModels().then((r) => {
      const enabled = (r.items || []).filter((m) => m.enabled)
      setModels(enabled)
      const def = enabled.find((m) => m.is_default)
      if (def) setModelId(def.id)
    }).catch(() => {})
  }, [])

  // auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  const refreshList = useCallback(async () => {
    try {
      const r = await listConversations()
      setConversations(r.items || [])
    } catch { /* ignore */ }
  }, [])

  // Refresh the conversation list after sending -- the backend fires
  // an LLM-based title generator as soon as the second user turn lands,
  // so we poll twice (1.5s + 4s) to catch the result without forcing
  // the operator to refresh manually. Lightweight GET; no UI jank.
  const titleTimer1 = useRef<number | null>(null)
  const titleTimer2 = useRef<number | null>(null)
  const clearPendingTitleRefresh = useCallback(() => {
    if (titleTimer1.current) { window.clearTimeout(titleTimer1.current); titleTimer1.current = null }
    if (titleTimer2.current) { window.clearTimeout(titleTimer2.current); titleTimer2.current = null }
  }, [])
  const scheduleTitleRefresh = useCallback(() => {
    clearPendingTitleRefresh()
    titleTimer1.current = window.setTimeout(() => { refreshList() }, 1500)
    titleTimer2.current = window.setTimeout(() => { refreshList() }, 4000)
  }, [clearPendingTitleRefresh, refreshList])

  const handleConfirmScan = useCallback(
    async (intent: ScanIntentData, nuclei: NucleiOptions, messageTs?: string) => {
      if (!intent) return
      setExecuting(true)
      try {
        const body: any = {
          source: "dialog",
          intent_text: messages
            .filter((m) => m.role === "user")
            .map((m) => m.content)
            .join("\n"),
          targets: intent.targets || [],
          modules:
            intent.modules && intent.modules.length
              ? intent.modules
              : ["sys_vuln", "baseline"],
          engine: intent.engine || "matcher",
        }
        // Forward nuclei knobs when the engine wants them. The backend
        // ignores them for engine=='matcher', so it's safe to always send.
        // V13: global (matcher + nuclei) also forwards them.
        if (intent.engine === "nuclei" || intent.engine === "global") {
          body.nuclei_ports = (nuclei.nuclei_ports || []).filter(
            (p: number) => Number.isInteger(p) && p >= 1 && p <= 65535,
          )
          body.nuclei_severity = nuclei.nuclei_severity || []
          body.nuclei_tags = nuclei.nuclei_tags || []
          body.nuclei_templates = (nuclei.nuclei_templates || "")
            .split(",")
            .map((s: string) => s.trim())
            .filter(Boolean)
          body.nuclei_timeout_sec = Number(nuclei.nuclei_timeout_sec) || 0
        }
        // F2 (2026-07-29): the user's scan message + assistant reply are
        // already persisted by /chat (via chatAssistant in handleSend), so
        // (V9 F2) we used to call chatConversation here too -- a redundant
        // LLM round-trip and persisted a *different* reply than the one the
        // operator saw.
        // Async path: backend enqueues to Redis Stream and returns the
        // task_id immediately. The TaskWorker (if running) picks it up
        // and runs the subgraph; the monitor page then shows the live
        // status. We deliberately avoid the legacy ?sync=1 path here --
        // it runs the subgraph inline in the HTTP request, which can take
        // many minutes for a real scan and would exceed the frontend 30s
        // axios timeout, leaving the operator stuck on "创建中…".
        // Always enqueue (sync=false). The legacy sync=true path runs
        // the full subgraph inline in the HTTP request, which can
        // take minutes for a real scan and easily exceeds the 30s
        // axios timeout -- the operator would see "创建中..." stuck
        // until the timeout fires, then silently revert.
        const task = await createScanTask(body)
        message.success("扫描任务已创建，正在跳转监控页…")
        // Tell the /scan task list to refresh next time it mounts; the
        // listener lives in ScanTaskPage.
        try { sessionStorage.setItem("secagent:task-created", String(Date.now())) } catch {}
        // Write the created task_id back onto the assistant message so a
        // future reload of this conversation shows "已创建任务 #xxx → 查看监控"
        // instead of an executable "执行扫描" button. Best-effort: a
        // failure here just means the link won't persist across reloads,
        // the current turn still navigates to the monitor.
        if (activeId && messageTs) {
          setMessages((prev) =>
            prev.map((m) => (m.ts === messageTs ? { ...m, task_id: task.task_id } : m)),
          )
          try {
            await patchMessage(activeId, messageTs, { task_id: task.task_id })
          } catch (e: any) {
            // Non-fatal: the in-memory state update above still shows
            // the link for the rest of this session.
            // eslint-disable-next-line no-console
            console.warn("patchMessage(task_id) failed", e?.message || e)
          }
        }
        navigate(`/scan-monitor/${task.task_id}`)
      } catch (e: any) {
        message.error(e?.response?.data?.detail || e?.message || "创建扫描任务失败")
      } finally {
        setExecuting(false)
      }
    },
    [activeId, messages, modelId, navigate],
  )

  // Hide the intent card without creating a task. We do not delete the
  // underlying message -- the LLM reply is still in history -- but we
  // mark it as dismissed so MessageRow stops rendering the card. The
  // operator can re-send their request to bring the card back.
  const handleCancel = useCallback(
    (messageTs?: string) => {
      if (!messageTs) return
      setMessages((prev) =>
        prev.map((m) => (m.ts === messageTs ? { ...m, intent: undefined } : m)),
      )
    },
    [],
  )

  // Used by historical intent cards to jump straight to the scan
  // monitor for an already-created task (rather than asking the
  // operator to re-create it).
  const handleViewTask = useCallback(
    (taskId: string) => {
      navigate(`/scan-monitor/${taskId}`)
    },
    [navigate],
  )

  const handleSend = useCallback(async (presetText?: string) => {
    const text = (presetText ?? input).trim()
    if (!text) return
    if (!activeId) {
      message.warning("请先点击左上角「新建对话」")
      return
    }

    const userMsg: ChatMessageEx = {
      role: "user", content: text, ts: new Date().toISOString(),
    }
    const pendingAssistant: ChatMessageEx = {
      role: "assistant", content: "", ts: new Date().toISOString(), pending: true,
    }
    setMessages((prev) => [...prev, userMsg, pendingAssistant])
    setInput("")
    setSending(true)
    try {
      // 关键修复：把对话历史一并传给后端，让 LLM 在多轮对话中能正确路由
      const res = await chatAssistant(activeId, text, modelId)
      setMessages((prev) => {
        const next = [...prev]
        const idx = next.findIndex((m) => m === pendingAssistant || (m.pending && m.role === "assistant"))
        const finalMsg: ChatMessageEx = {
          role: "assistant",
          content: res.reply,
          // V9 follow-up: adopt the server's authoritative `ts` so a
          // later patchMessage(task_id) is guaranteed to hit the
          // same PG row. Microsecond / timezone drift between client
          // and server would otherwise make patchMessage silently miss.
          ts: res.assistant_ts || new Date().toISOString(),
          route: res.intent,
          sources: res.sources,
          intent: res.intent === "scan" ? parseIntentFromSources(res.sources) : undefined,
        }
        if (idx >= 0) next[idx] = finalMsg
        else next.push(finalMsg)
        return next
      })
      if (res.intent === "scan" && res.sources && res.sources.length > 0) {
        message.success("已识别扫描意图，点下方卡片「执行扫描」即可创建任务")
      }
      scheduleTitleRefresh()
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e?.message || "发送失败"
      setMessages((prev) => {
        const next = [...prev]
        const idx = next.findIndex((m) => m === pendingAssistant || (m.pending && m.role === "assistant"))
        if (idx >= 0) {
          next[idx] = {
            role: "assistant", content: detail,
            ts: new Date().toISOString(), error: detail,
          }
        }
        return next
      })
      message.error(detail)
    } finally {
      setSending(false)
      inputRef.current?.focus()
    }
  }, [activeId, input, modelId])

  // Clean up title refresh timers on unmount.
  useEffect(() => () => clearPendingTitleRefresh(), [clearPendingTitleRefresh])



  // 2026-07-29 UX upgrade: dedup against existing "new" conversations.
  // Default titles are produced by the backend (newConversation) and by
  // the Chinese UI ("新对话") / English fallback ("Untitled"). If any
  // of those exists we switch to it instead of creating a duplicate.
  const EMPTY_TITLES = new Set(["", "新对话", "新会话", "未命名对话", "Untitled", "Untitled Chat"])
  const handleNew = useCallback(async () => {
    // 2026-07-29 UX upgrade: dedup against existing "untouched" new
    // conversations. A conversation counts as "untouched" only if:
    //   1) its title is still the default placeholder, AND
    //   2) it has zero messages in the persisted history.
    // The original implementation only checked the title, which would
    // mis-classify a conversation whose user has since typed a
    // question and then deleted the placeholder title.
    try {
      for (const c of conversations) {
        if (!EMPTY_TITLES.has(c.title || "")) continue
        try {
          const conv = await getConversation(c.id)
          if ((conv.messages || []).length === 0) {
            setActiveId(c.id)
            setMessages([])
            setModelId(conv.model_id)
            message.info("已存在未使用的新对话，已为您切换")
            return
          }
          // Has a placeholder title but already has turns; skip and
          // keep looking so we can find a truly empty one. If none
          // exists the for-loop falls through to createConversation.
        } catch {
          // GET failed; treat as "occupied" so we create a new one
          // rather than risk overwriting another window.
          continue
        }
      }
      const conv = await createConversation()
      setActiveId(conv.id)
      setMessages([])
      setInput("") // V13 P2-21: new conversation must start with a clean input
      refreshList()
    } catch {
      message.error("新建对话失败")
    }
  }, [refreshList, conversations])

  const handleSelect = useCallback(async (id: string) => {
    setLoadingConv(true)
    try {
      const conv = await getConversation(id)
      setActiveId(id)
      // convert server shape to extended (no route/sources on load -- they are ephemeral)
      setMessages((conv.messages || []).map((m) => ({ ...m })))
      setModelId(conv.model_id)
      // V13 P2-21: reset per-conversation transient state so switching to
      // another conversation never leaks the previous one's draft input,
      // in-flight send or executing-scan flag into the new view.
      setInput("")
      setSending(false)
      setExecuting(false)
    } catch {
      message.error("加载对话失败")
    } finally {
      setLoadingConv(false)
    }
  }, [])

  const handleDelete = useCallback(async (id: string) => {
    try {
      await deleteConversation(id)
      if (activeId === id) {
        setActiveId(null)
        setMessages([])
      }
      refreshList()
    } catch {
      message.error("删除失败")
    }
  }, [activeId, refreshList])

  const handleModelChange = useCallback(async (id: number | null) => {
    setModelId(id)
    if (activeId) {
      try { await updateConversation(activeId, { model_id: id }) } catch { /* ignore */ }
    }
  }, [activeId])

  const onKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }, [handleSend])

  const currentModelLabel = useMemo(() => {
    const m = models.find((x) => x.id === modelId)
    return m ? m.name : "未选模型"
  }, [models, modelId])

  return (
    <div className="chat-shell">
      {/* 左侧会话列表 */}
      <aside className="chat-sidebar" style={{ display: collapsed ? "none" : "flex" }}>
        <div className="chat-sidebar-head">
          <button className="new-btn" onClick={handleNew}>
            <PlusOutlined /> 新建对话
          </button>
        </div>
        <div className="chat-sidebar-list">
          {conversations.length === 0 ? (
            <div className="chat-sidebar-empty">还没有对话<br/>点上面的按钮开始</div>
          ) : (
            <List
              size="small"
              dataSource={conversations}
              renderItem={(c) => (
                <div
                  className={`chat-conv-item ${activeId === c.id ? "active" : ""}`}
                  onClick={() => handleSelect(c.id)}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="title">{c.title || "未命名对话"}</div>
                    <div className="meta">{c.updated_at?.slice(5, 16) || ""}</div>
                  </div>
                  <Popconfirm
                    title="删除该对话？"
                    onConfirm={(e) => { e?.stopPropagation(); handleDelete(c.id) }}
                    onCancel={(e) => e?.stopPropagation()}
                  >
                    <button
                      className="del-btn"
                      onClick={(e) => e.stopPropagation()}
                      title="删除"
                    >
                      <DeleteOutlined />
                    </button>
                  </Popconfirm>
                </div>
              )}
            />
          )}
        </div>
      </aside>

      {/* 主对话区 */}
      <main className="chat-main">
        <header className="chat-topbar">
          <div className="title">
            <Button
              type="text"
              size="small"
              icon={<MessageOutlined />}
              onClick={() => setCollapsed((v) => !v)}
              title={collapsed ? "显示侧栏" : "隐藏侧栏"}
            />
            <RobotOutlined className="title-icon" />
            <span>SecAgent 助手</span>
            <Tag color="blue" icon={<RobotOutlined />} style={{ marginRight: 0 }}>
              AI · {currentModelLabel}
            </Tag>
            <span className="badge">扫描 · 项目问答 · 联网搜索</span>
          </div>
          <div className="right">
            <Select
              size="small"
              style={{ width: 200 }}
              value={modelId ?? undefined}
              onChange={handleModelChange}
              placeholder="选择模型"
              options={models.map((m) => ({
                label: `${m.name}${m.is_default ? " (默认)" : ""}`,
                value: m.id,
              }))}
            />
          </div>
        </header>

        <div className="chat-stream" ref={scrollRef}>
          {!activeId ? (
            <WelcomeScreen onPick={(t) => { setInput(t); inputRef.current?.focus() }} />
          ) : loadingConv ? (
            <div style={{ textAlign: "center", marginTop: 80 }}>
              <Spin />
            </div>
          ) : messages.length === 0 ? (
            <EmptyState onPick={(t) => handleSend(t)} />
          ) : (
            <div className="chat-stream-inner">
              {messages.map((m, i) => (
                <MessageRow
                  key={i}
                  msg={m}
                  onConfirmScan={handleConfirmScan}
                  onCancel={handleCancel}
                  executing={executing}
                  onViewTask={handleViewTask}
                />
              ))}
            </div>
          )}
        </div>

        <div className="chat-input-wrap">
          <div className="chat-input-inner">
            <Input.TextArea
              ref={inputRef as any}
              autoSize={{ minRows: 1, maxRows: 6 }}
              placeholder={activeId ? "发消息，Enter 发送，Shift+Enter 换行" : "请先新建对话"}
              value={input}
              disabled={!activeId || sending}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
            />
            <div className="chat-input-toolbar">
              <div className="left">
                <Tooltip title="当前使用的模型">
                  <span className="model-pill">🤖 {currentModelLabel}</span>
                </Tooltip>
                <span className="hint">Enter 发送 · Shift+Enter 换行</span>
              </div>
              <Button
                className="send-btn"
                type="primary"
                icon={sending ? <span className="typing-dot"><span/><span/><span/></span> : <SendOutlined />}
                loading={sending}
                disabled={!activeId || !input.trim()}
                onClick={() => handleSend()}
              />
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

// ── 欢迎屏 / 空状态 ──────────────────────────────────────
function WelcomeScreen({ onPick }: { onPick: (t: string) => void }) {
  const list = [
    { icon: <ScanOutlined />, text: "帮我扫描 test 组的主机，做漏洞扫描 + 基线" },
    { icon: <BulbOutlined />, text: "系统的整体架构是怎样的？" },
    { icon: <GlobalOutlined />, text: "最近有什么严重的 CVE？" },
    { icon: <MessageOutlined />, text: "如何把一台新主机接入这个系统？" },
  ]
  return (
    <div className="chat-empty">
      <div className="empty-icon"><RobotOutlined /></div>
      <div className="empty-title">你好，我是 SecAgent 助手</div>
      <div className="empty-sub">扫描任务 · 项目问答 · 联网搜索，一个对话框搞定</div>
      <div className="suggestions">
        {list.map((s, i) => (
          <button key={i} className="suggestion" onClick={() => onPick(s.text)}>
            <span className="ico">{s.icon}</span>
            <span>{s.text}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

function EmptyState({ onPick }: { onPick: (t: string) => void }) {
  return <WelcomeScreen onPick={onPick} />
}

// ── 单条消息 ────────────────────────────────────────────
function MessageRow({
  msg, onConfirmScan, onCancel, executing, onViewTask,
}: {
  msg: ChatMessageEx
  onConfirmScan: (intent: ScanIntentData, nuclei: NucleiOptions, messageTs?: string) => void
  onCancel: (messageTs?: string) => void
  executing: boolean
  onViewTask: (taskId: string) => void
}) {
  const isUser = msg.role === "user"
  if (msg.pending) {
    return (
      <div className={`chat-row assistant`}>
        <div className="chat-avatar"><RobotOutlined /></div>
        <div className="chat-bubble routing">
          <span className="typing-dot"><span/><span/><span/></span>
          &nbsp;正在思考…
        </div>
      </div>
    )
  }
  return (
    <div className={`chat-row ${isUser ? "user" : "assistant"}`}>
      <div className="chat-avatar">
        {isUser ? <UserOutlined /> : <RobotOutlined />}
      </div>
      <div style={{ display: "flex", flexDirection: "column", maxWidth: "78%" }}>
        {msg.route && !isUser && (
          <span className={`chat-route-tag ${msg.route}`}>
            {ROUTE_LABEL[msg.route]?.text || msg.route}
          </span>
        )}
        <div className="chat-bubble">
            {isUser ? msg.content : <Markdown source={msg.content} />}
          </div>
        {/* 扫描意图卡片 */}
        {msg.intent && msg.route === "scan" && (
          <IntentCard
            intent={msg.intent}
            onConfirm={onConfirmScan}
            onCancel={onCancel}
            disabled={executing}
            taskId={msg.task_id}
            messageTs={msg.ts}
            onViewTask={onViewTask}
          />
        )}
        {/* 来源列表 */}
        {msg.sources && msg.sources.length > 0 && msg.route !== "scan" && (
          <SourcesBlock sources={msg.sources} />
        )}
      </div>
    </div>
  )
}

// ── 扫描意图卡片 ────────────────────────────────────────
const NUCLEI_SEVERITY_OPTIONS = [
  { label: "critical", value: "critical" },
  { label: "high", value: "high" },
  { label: "medium", value: "medium" },
  { label: "low", value: "low" },
  { label: "info", value: "info" },
]

const NUCLEI_TAGS_OPTIONS = [
  { label: "rce", value: "rce" },
  { label: "auth-bypass", value: "auth-bypass" },
  { label: "sqli", value: "sqli" },
  { label: "exposure", value: "exposure" },
]

function IntentCard({
  intent, onConfirm, onCancel, disabled, taskId, messageTs, onViewTask,
}: {
  intent: ScanIntentData
  onConfirm: (intent: ScanIntentData, nuclei: NucleiOptions, messageTs?: string) => void
  /** Hide this card without creating a task. The user can re-send their
   * request from the chat input to bring the card back. */
  onCancel: (messageTs?: string) => void
  disabled: boolean
  /** Set once the operator clicks “执行扫描” and the backend created a task.
   * When present, the card switches from an executable button to a static
   * “已创建任务 #xxx → 查看监控” link so historical cards on
   * reload don’t re-prompt the operator to create the task again. */
  taskId?: string
  /** ts of the assistant message this card belongs to; used to write back
   * task_id via patchMessage so the link survives a reload. */
  messageTs?: string
  /** Navigates to the scan monitor for an already-created task. */
  onViewTask?: (taskId: string) => void
}) {
  // 2026-07-29 UX upgrade: business-group fast-path. If the LLM didn't
  // pick concrete targets (very common when the operator asks to scan
  // "all order-service hosts"), the operator can pick a business group
  // here and we expand it into the host list before confirming.
  const initialTargets = intent.targets?.length ? intent.targets : []
  // Defense in depth: the backend also strips LLM-emitted type prefixes
  // (group:/host:/ip:) before persisting the intent, but older
  // conversations in PG may still carry the prefixed form. Normalize
  // here so the auto-fill works regardless of which path produced the
  // intent, and so the displayed targets never leak the type tag.
  const TARGET_PREFIX_RE = /^(group|host|ip|hostname|grp):/i
  const normalizeTarget = (t: string) => t.replace(TARGET_PREFIX_RE, "").trim()
  const normalizedInitial = initialTargets.map(normalizeTarget).filter(Boolean)
  // V9 4.5: single Set tracks every host added by either the group
  // shortcut or the per-host multi-select. The operator can remove
  // any host (the Set supports add / delete / clear). Previously
  // the group shortcut pushed items into extraTargets which had no
  // way to retract them.
  const [pickedHosts, setPickedHosts] = useState<Set<string>>(new Set())
  const [groups, setGroups] = useState<HostGroup[]>([])
  const [hostByGroup, setHostByGroup] = useState<Record<string, string[]>>({})
  const [pickedGroup, setPickedGroup] = useState<string | undefined>(undefined)
  // `bareInitial` = initial targets that are NOT consumed by an
  // auto-picked business group, so the operator does not see "test"
  // and "Rocky001" duplicated in the 目标 row when the LLM said
  // "扫描 test 组". Resolved at render time once `groups` is loaded.
  const bareInitial = (() => {
    if (groups.length === 0) return normalizedInitial
    const groupNames = new Set(groups.map((g) => g.name))
    return normalizedInitial.filter((t) => !groupNames.has(t))
  })()
  useEffect(() => {
    listGroups().then((r) => setGroups((r.items as HostGroup[]) || [])).catch(() => {})
  }, [])
  // Auto-fill: when the LLM extracted a target that matches an existing
  // business group (“扫描 test 组” → targets:["test"] / ["group:test"]), pre-select that
  // group and fold its hosts into pickedHosts so the operator does not
  // have to redo the dropdown selection the LLM just implied.
  useEffect(() => {
    if (groups.length === 0) return
    if (pickedGroup) return // operator has already chosen something; don’t override
    if (!normalizedInitial.length) return
    const groupNames = new Set(groups.map((g) => g.name))
    const matched = normalizedInitial.find((t) => groupNames.has(t))
    if (matched) {
      onPickGroup(matched)
    }
    // We intentionally only depend on `groups` here. `normalizedInitial` /
    // `pickedGroup` are read inside but a change to them is a *result* of
    // this effect (or a user action), not a new intent -- re-running would
    // cause an infinite loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups])
  const onPickGroup = async (g: string | undefined) => {
    setPickedGroup(g)
    if (!g || hostByGroup[g]) return
    try {
      const r = await listHosts({ group: g })
      const hosts = (r.items || []).map((h: Host) => h.hostname).filter(Boolean)
      setHostByGroup((prev) => ({ ...prev, [g]: hosts }))
      // Fold into the single Set so the operator can later remove
      // individual hosts via the multi-select.
      setPickedHosts((prev) => {
        const next = new Set(prev)
        for (const h of hosts) next.add(h)
        return next
      })
    } catch { /* ignore */ }
  }
  // `mergedTargets` is what we actually send to /vulnscan/tasks. It is the
  // union of (initial targets that are NOT a known group name) +
  // (manually-picked hosts). Group names that have been auto-resolved
  // into hosts are NOT included so the API does not see "test" as a
  // phantom target alongside its member hostnames.
  const mergedTargets = Array.from(new Set([...bareInitial, ...pickedHosts]))
  const modules = intent.modules?.length ? intent.modules : ["sys_vuln", "baseline"]
  const engine = intent.engine || "matcher"
  const showNuclei = engine === "nuclei" || engine === "global"
  const [nuclei, setNuclei] = useState<NucleiOptions>({
    nuclei_ports: intent.nuclei_ports || [],
    nuclei_severity: intent.nuclei_severity || [],
    nuclei_tags: intent.nuclei_tags || [],
    nuclei_templates: (intent.nuclei_templates || []).join(", "),
    nuclei_timeout_sec: intent.nuclei_timeout_sec || 0,
  })
  // Note: we always create the task asynchronously (enqueue + return
  // task_id immediately). The legacy ?sync=1 path runs the full
  // subgraph inline in the HTTP request, which can take many minutes
  // for a real matcher/nuclei scan and easily blows past the frontend
  // 30s axios timeout -- the request then aborts and the operator
  // sees a stuck “创建中…” button that silently reverts. The async path
  // returns a task_id in milliseconds, navigates to the monitor, and
  // the worker drives the scan from there.
  const [advanced, setAdvanced] = useState(false)
  const canConfirm = mergedTargets.length > 0

  // Compact human-readable description strings for the minimal summary
  // view. We collapse long host lists to "X, ..., 还有 N 台" so the card
  // never explodes vertically for big groups.
  const MAX_HOSTS = 5
  const hostList = mergedTargets
  const hostPreview = hostList.slice(0, MAX_HOSTS).join(", ")
  const hostMore = hostList.length - MAX_HOSTS
  const hostDescription = hostList.length === 0
    ? "暂未识别到主机"
    : (hostList.length <= MAX_HOSTS
        ? hostPreview
        : hostPreview + "，还有 " + hostMore + " 台")

  // `targetDescription` -- the user-facing target label.
  // If the LLM extracted a single business-group name, say "test 组".
  // Otherwise show the joined target list (e.g. for bare hostnames/IPs).
  const matchedGroupName = pickedGroup || (
    groups.length > 0
      ? normalizedInitial.find((t) => groups.some((g) => g.name === t))
      : undefined
  )
  const targetDescription = matchedGroupName
    ? matchedGroupName + " 组"
    : (bareInitial.length ? bareInitial.join(", ") : hostDescription)

  // `moduleDescription` -- join the localized module names.
  const moduleDescription = modules.map((m) => MODULE_NAME[m] || m).join(" + ")

  return (
    <div className="intent-card intent-card-compact">
      <h4><ThunderboltOutlined /> 已识别扫描意图</h4>
      <div className="intent-summary">
        <div className="intent-summary-line">
          <span className="intent-summary-icon">🎯</span>
          <span className="intent-summary-label">将扫描</span>
          <span className="intent-summary-target">{targetDescription}</span>
        </div>
        <div className="intent-summary-line intent-summary-sub">
          <span className="intent-summary-sub-text">主机：{hostDescription}</span>
        </div>
        <div className="intent-summary-line">
          <span className="intent-summary-icon">🔍</span>
          <span className="intent-summary-label">扫描项目</span>
          <span className="intent-summary-modules">{moduleDescription}</span>
        </div>
        <div className="intent-summary-line intent-summary-sub">
          <span className="intent-summary-sub-text">引擎：{engine}（异步任务）</span>
        </div>
      </div>
      {showNuclei && (
        <div className="intent-advanced">
          <button
            type="button"
            className="intent-advanced-toggle"
            onClick={() => setAdvanced((v) => !v)}
          >
            {advanced ? "收起 nuclei 高级选项" : "展开 nuclei 高级选项"}
          </button>
          {advanced && (
            <div className="intent-nuclei-grid">
              <label>
                <span>端口</span>
                <Select
                  mode="tags"
                  size="small"
                  style={{ width: "100%" }}
                  value={nuclei.nuclei_ports.map(String)}
                  onChange={(v) => setNuclei((s) => ({
                    ...s,
                    nuclei_ports: (v || [])
                      .map((x) => Number(x))
                      .filter((p: number) => Number.isInteger(p) && p >= 1 && p <= 65535),
                  }))}
                  placeholder="留空 = 全部端口（可输入 80,443,8080）"
                />
              </label>
              <label>
                <span>严重等级</span>
                <Select
                  mode="multiple"
                  size="small"
                  style={{ width: "100%" }}
                  value={nuclei.nuclei_severity}
                  onChange={(v) => setNuclei((s) => ({ ...s, nuclei_severity: v }))}
                  options={NUCLEI_SEVERITY_OPTIONS}
                  placeholder="留空 = 全部"
                />
              </label>
              <label>
                <span>标签</span>
                <Select
                  mode="tags"
                  size="small"
                  style={{ width: "100%" }}
                  value={nuclei.nuclei_tags}
                  onChange={(v) => setNuclei((s) => ({ ...s, nuclei_tags: v }))}
                  options={NUCLEI_TAGS_OPTIONS}
                  placeholder="如 rce, auth-bypass"
                />
              </label>
              <label>
                <span>模板 ID 列表</span>
                <Input
                  size="small"
                  value={nuclei.nuclei_templates}
                  onChange={(e) => setNuclei((s) => ({ ...s, nuclei_templates: e.target.value }))}
                  placeholder="cves/2024/CVE-2024-1234, exposures/..."
                />
              </label>
              <label>
                <span>超时 (秒)</span>
                <Input
                  size="small"
                  type="number"
                  value={nuclei.nuclei_timeout_sec}
                  onChange={(e) => setNuclei((s) => ({ ...s, nuclei_timeout_sec: Number(e.target.value) || 0 }))}
                  placeholder="0 = runner 默认 600s"
                />
              </label>
            </div>
          )}
        </div>
      )}
      {!canConfirm && (
        <div className="intent-warning">
          ⚠ 还没识别到目标主机/组，请在对话里补充“扫描 XX 组”或“扫描 IP 1.2.3.4”
        </div>
      )}
      <div className="actions">
        {taskId ? (
          // Historical / already-executed card. Show a static link to
          // the monitor page instead of an executable button.
          <>
            <div className="intent-task-info">
              <span className="intent-task-badge">
                ✓ 已创建任务，任务ID：
              </span>
              <code className="intent-task-id">{taskId}</code>
            </div>
            <a
              className="btn-confirm"
              href={`/scan-monitor/${taskId}`}
              onClick={(e) => {
                e.preventDefault()
                onViewTask?.(taskId)
              }}
            >
              查看任务 →
            </a>
          </>
        ) : (
          <>
            <button
              className="btn-cancel"
              disabled={disabled}
              onClick={() => onCancel(messageTs)}
            >
              取消创建任务
            </button>
            <button
              className="btn-confirm"
              disabled={disabled || !canConfirm}
              onClick={() => onConfirm({ ...intent, targets: mergedTargets }, nuclei, messageTs)}
            >
              {disabled ? "创建中…" : "立即创建扫描任务"}
            </button>
          </>
        )}
      </div>
    </div>
  )
}

// ── 来源列表 ────────────────────────────────────────────
function SourcesBlock({ sources }: { sources: ChatSource[] }) {
  if (!sources?.length) return null
  return (
    <div className="sources-block">
      <div className="sources-title">📎 参考资料</div>
      {sources.map((s, i) => (
        <a
          key={i}
          className="source-item"
          href={s.url || "#"}
          target={s.url ? "_blank" : undefined}
          rel="noreferrer"
          onClick={(e) => { if (!s.url) e.preventDefault() }}
        >
          <div className="src-title">[{i + 1}] {s.title}</div>
          {s.url && <div className="src-url">{s.url}</div>}
          {s.snippet && (
            <div style={{ color: "#9ca3af", fontSize: 11, marginTop: 4 }}>
              {s.snippet.slice(0, 160)}{s.snippet.length > 160 ? "…" : ""}
            </div>
          )}
        </a>
      ))}
    </div>
  )
}

// 简易 Spinner 占位，避免引入 useState hook 的额外依赖
function Spin() {
  return <span className="typing-dot"><span/><span/><span/></span>
}

function parseIntentFromSources(sources: ChatSource[] | undefined): ScanIntentData | undefined {
  if (!sources || sources.length === 0) return undefined
  const intentSrc = sources.find((s) => s.title === "intent" && s.snippet)
  if (!intentSrc?.snippet) return undefined
  try {
    const parsed = JSON.parse(intentSrc.snippet)
    return {
      targets: parsed.targets || [],
      modules: parsed.modules || [],
      engine: parsed.engine || "matcher",
      resource_limit: parsed.resource_limit,
      schedule: parsed.schedule,
    }
  } catch {
    return undefined
  }
}
