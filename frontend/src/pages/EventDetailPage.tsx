import { useEffect, useState } from "react"
import { Typography, Spin, Descriptions, Tag, Timeline, Button, Space, message, Collapse, Empty, Input } from "antd"
import { Card } from "antd"
import { ArrowLeftOutlined, CheckOutlined, CloseOutlined, BugOutlined, SafetyOutlined, SearchOutlined } from "@ant-design/icons"
import { useParams, useNavigate } from "react-router-dom"
import api, { getEventDetail, approveEvent, getSseToken } from "../api/client"
import { useAuth } from "../context/AuthContext"
import type { EventRecord } from "../types"

const NODE_ICONS: Record<string, React.ReactNode> = {
  entry: <SearchOutlined />, orchestrator: <SafetyOutlined />,
  investigate: <BugOutlined />, aggregator: <SafetyOutlined />,
  respond: <SafetyOutlined />,
}

export default function EventDetailPage() {
  const { eventId } = useParams<{ eventId: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const [ev, setEv] = useState<EventRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [approving, setApproving] = useState(false)
  const [note, setNote] = useState("")

  const canApprove = (user?.role === "admin" || user?.role === "responder") && ev?.status === "pending_approval"

  useEffect(() => {
    if (!eventId) return
    setLoading(true)
    getEventDetail(eventId).then(setEv).catch(() => message.error("获取事件详情失败")).finally(() => setLoading(false))
  }, [eventId])

  // SSE: live-refresh trace steps / status / approval as the pipeline progresses.
  useEffect(() => {
    if (!eventId) return
    // F2 (2026-07-21): mint a 60s scoped SSE token first; reuse
    // api.defaults.baseURL so reverse-proxy / k8s ingress keep working.
    if (!eventId) return
    if (!localStorage.getItem("token")) return
    // Capture the narrowed string so the async IIFE and inner helper both
    // see it as `string`, not `string | undefined`.
    const eventIdStr: string = eventId
    let source: EventSource | null = null
    let cancelled = false
    ;(async () => {
      try {
        const shortToken = await getSseToken("events")
        if (cancelled) return
        const base = (api.defaults.baseURL || "").replace(/\/+$/, "")
        // base 已含 /api/v1，只拼 /events/...（不能重复 /api/v1，否则 404 致
        // EventSource 无限重连占满连接数致所有请求阻塞）。
        source = new EventSource(`${base}/events/${eventIdStr}/stream?token=${shortToken}`)
        wireSource(source)
      } catch (err) { console.warn("event_detail_sse_token_failed", err) }
    })()
    function wireSource(source: EventSource) {
    source.onmessage = (e) => {
      if (e.data && e.data !== ": heartbeat") {
        getEventDetail(eventIdStr).then(setEv).catch(() => {})
      }
    }
    // 防重连风暴：404/网络错误 readyState=CLOSED 时主动 close，避免无限重连
    // 占满浏览器同域连接数致所有请求阻塞。
    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) source.close()
    }
    }
    // useEffect cleanup（修复：原 return 在 wireSource 内部被丢弃，EventSource 永不关闭）
    return () => {
      cancelled = true
      source?.close()
    }
  }, [eventId])

  const doApprove = async (action: "approved" | "rejected") => {
    if (!eventId) return; setApproving(true)
    try { await approveEvent(eventId, action, note); message.success(action === "approved" ? "已批准" : "已驳回"); getEventDetail(eventId).then(setEv) }
    catch { message.error("操作失败") }
    finally { setApproving(false) }
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />
  if (!ev) return <Empty description="事件不存在" />

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/events")}>返回</Button>
        <Typography.Title level={4} style={{ margin: 0 }}>事件详情</Typography.Title>
      </Space>

      <Descriptions title="概览" column={3} bordered size="small" style={{ marginBottom: 16 }}>
        <Descriptions.Item label="事件 ID" span={3}><Typography.Text copyable>{ev.event_id}</Typography.Text></Descriptions.Item>
        <Descriptions.Item label="来源">{ev.source}</Descriptions.Item>
        <Descriptions.Item label="定级">{ev.priority ? <Tag color={ev.priority === "high" ? "red" : ev.priority === "medium" ? "orange" : "default"}>{ev.priority}</Tag> : "-"}</Descriptions.Item>
        <Descriptions.Item label="耗时">{ev.duration_ms ? `${ev.duration_ms}ms` : "-"}</Descriptions.Item>
        <Descriptions.Item label="结论">{ev.final_verdict ? <Tag color={ev.final_verdict === "true_positive" ? "red" : "green"}>{ev.final_verdict}</Tag> : "-"}</Descriptions.Item>
        <Descriptions.Item label="置信度">{ev.confidence != null ? `${(ev.confidence * 100).toFixed(0)}%` : "-"}</Descriptions.Item>
        <Descriptions.Item label="状态"><Tag>{ev.status}</Tag></Descriptions.Item>
        <Descriptions.Item label="事件描述" span={3}>{ev.sanitized_text}</Descriptions.Item>
        {ev.mitre_ttps?.length > 0 && <Descriptions.Item label="MITRE TTP" span={3}>{ev.mitre_ttps.map((t) => <Tag key={t}>{t}</Tag>)}</Descriptions.Item>}
      </Descriptions>

      <Typography.Title level={5}>推理链</Typography.Title>
      {ev.trace?.length > 0 ? (
        <Timeline items={ev.trace.map((step, i) => ({
          dot: NODE_ICONS[step.node],
          color: step.node === "ignore" ? "gray" : step.node === "respond" ? "blue" : step.node === "aggregator" ? "green" : "blue",
          children: (
            <Collapse ghost size="small" items={[{
              key: String(i),
              label: (
                <Space>
                  <Tag color="blue">{step.node}</Tag>
                  <strong>{step.action}</strong>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>{step.summary}</Typography.Text>
                </Space>
              ),
              children: (
                <div>
                  {step.timestamp && <Typography.Paragraph style={{ fontSize: 12, margin: 0 }} type="secondary">{new Date(step.timestamp).toLocaleString()}</Typography.Paragraph>}
                  {Object.keys(step.details).length > 0 && (
                    <pre style={{ fontSize: 12, background: "#f6f8fa", padding: 8, borderRadius: 4, maxHeight: 200, overflow: "auto" }}>
                      {JSON.stringify(step.details, null, 2)}
                    </pre>
                  )}
                </div>
              ),
            }]} />
          ),
        }))} />
      ) : <Empty description="暂无推理轨迹" />}

      {canApprove && (
        <Card style={{ marginTop: 16 }}>
          <Space direction="vertical" style={{ width: "100%" }}>
            <Input.TextArea rows={2} placeholder="审批备注（可选）" value={note} onChange={(e) => setNote(e.target.value)} />
            <Space>
              <Button type="primary" icon={<CheckOutlined />} loading={approving} onClick={() => doApprove("approved")}>批准</Button>
              <Button danger icon={<CloseOutlined />} loading={approving} onClick={() => doApprove("rejected")}>驳回</Button>
            </Space>
          </Space>
        </Card>
      )}

      {ev.approvals?.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <Typography.Title level={5}>审批历史</Typography.Title>
          <Timeline items={ev.approvals.map((a: any) => ({
            color: a.action === "approved" ? "green" : "red",
            children: <div><Tag color={a.action === "approved" ? "success" : "error"}>{a.action}</Tag> {a.actor} ({a.role}){a.note ? `: ${a.note}` : ""}</div>,
          }))} />
        </div>
      )}
    </div>
  )
}
