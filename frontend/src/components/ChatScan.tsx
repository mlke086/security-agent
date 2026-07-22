import { useEffect, useRef, useState, useMemo, useCallback } from "react"
import {
  Input, Button, Select, message, List, Popconfirm, Tooltip,
} from "antd"
import {
  SendOutlined, PlusOutlined, ThunderboltOutlined, DeleteOutlined,
  RobotOutlined, UserOutlined, MessageOutlined,
  BulbOutlined, ScanOutlined, GlobalOutlined,
} from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import {
  listConversations, createConversation, getConversation, deleteConversation,
  chatConversation, updateConversation, listModels,
  chatAssistant, createScanTask,
  type ConversationSummary, type ChatMessage, type LlmModel,
  type ChatRoute, type ChatSource,
} from "../api/client"
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
  intent?: ScanIntentData | null
  /** 是否正在等待流式响应 */
  pending?: boolean
  /** 失败时的错误提示 */
  error?: string
}

interface ScanIntentData {
  targets: string[]
  modules: string[]
  engine?: string
  resource_limit?: Record<string, unknown>
  schedule?: string | null
}

const ROUTE_LABEL: Record<ChatRoute, { text: string; cls: string }> = {
  scan:    { text: "🔍 扫描意图识别", cls: "scan" },
  project: { text: "📚 项目文档问答", cls: "project" },
  web:     { text: "🌐 联网搜索", cls: "web" },
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

  const handleNew = useCallback(async () => {
    try {
      const conv = await createConversation()
      setActiveId(conv.id)
      setMessages([])
      refreshList()
    } catch {
      message.error("新建对话失败")
    }
  }, [refreshList])

  const handleSelect = useCallback(async (id: string) => {
    setLoadingConv(true)
    try {
      const conv = await getConversation(id)
      setActiveId(id)
      // convert server shape to extended (no route/sources on load -- they are ephemeral)
      setMessages((conv.messages || []).map((m) => ({ ...m })))
      setModelId(conv.model_id)
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
          ts: new Date().toISOString(),
          route: res.intent,
          sources: res.sources,
          intent: res.intent === "scan" ? parseIntentFromSources(res.sources) : null,
        }
        if (idx >= 0) next[idx] = finalMsg
        else next.push(finalMsg)
        return next
      })
      if (res.intent === "scan" && res.sources && res.sources.length > 0) {
        message.success("已识别扫描意图，点下方卡片「执行扫描」即可创建任务")
      }
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

  const handleConfirmScan = useCallback(async (intent: ScanIntentData) => {
    if (!intent) return
    setExecuting(true)
    try {
      const body = {
        source: "dialog",
        intent_text: messages.filter((m) => m.role === "user").map((m) => m.content).join("\n"),
        targets: intent.targets || [],
        modules: (intent.modules && intent.modules.length) ? intent.modules : ["sys_vuln", "baseline"],
        engine: intent.engine || "matcher",
      }
      // Persist this turn to the scan conversation (keeps history in sync
      // with the sidebar list). The actual task creation goes through the
      // /vulnscan/tasks endpoint below.
      try {
        await chatConversation(activeId!, body.intent_text, modelId, false)
      } catch { /* best-effort */ }
      const task = await createScanTask(body)
      message.success("扫描任务已创建，正在跳转监控页…")
      navigate(`/scan-monitor/${task.task_id}`)
    } catch (e: any) {
      message.error(e?.response?.data?.detail || e?.message || "创建扫描任务失败")
    } finally {
      setExecuting(false)
    }
  }, [activeId, messages, modelId, navigate])

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
                  executing={executing}
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
  msg, onConfirmScan, executing,
}: {
  msg: ChatMessageEx
  onConfirmScan: (intent: ScanIntentData) => void
  executing: boolean
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
        <div className="chat-bubble">{msg.content}</div>
        {/* 扫描意图卡片 */}
        {msg.intent && msg.route === "scan" && (
          <IntentCard intent={msg.intent} onConfirm={onConfirmScan} disabled={executing} />
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
function IntentCard({
  intent, onConfirm, disabled,
}: { intent: ScanIntentData; onConfirm: (i: ScanIntentData) => void; disabled: boolean }) {
  const targets = intent.targets?.length ? intent.targets : ["（未指定，请在对话中补充）"]
  const modules = intent.modules?.length ? intent.modules : ["sys_vuln", "baseline"]
  const engine = intent.engine || "matcher"
  return (
    <div className="intent-card">
      <h4><ThunderboltOutlined /> 已识别扫描意图</h4>
      <div className="intent-row">
        <span className="label">目标：</span>
        {targets.map((t, i) => <span key={i} className="value">{t}</span>)}
      </div>
      <div className="intent-row">
        <span className="label">模块：</span>
        {modules.map((m, i) => <span key={i} className="value">{MODULE_NAME[m] || m}</span>)}
      </div>
      <div className="intent-row">
        <span className="label">引擎：</span>
        <span className="value">{engine}</span>
      </div>
      <div className="actions">
        <button className="btn-discard" disabled={disabled}>
          调整一下
        </button>
        <button
          className="btn-confirm"
          disabled={disabled || (intent.targets?.length ?? 0) === 0}
          onClick={() => onConfirm(intent)}
        >
          {disabled ? "创建中…" : "执行扫描"}
        </button>
      </div>
      {(!intent.targets || intent.targets.length === 0) && (
        <div style={{ marginTop: 8, fontSize: 12, color: "#d48806" }}>
          ⚠ 还没识别到目标主机/组，请在对话里告诉我"扫描 XX 组"或"扫描 IP 1.2.3.4"
        </div>
      )}
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

function parseIntentFromSources(sources: ChatSource[] | undefined): ScanIntentData | null {
  if (!sources || sources.length === 0) return null
  const intentSrc = sources.find((s) => s.title === "intent" && s.snippet)
  if (!intentSrc?.snippet) return null
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
    return null
  }
}