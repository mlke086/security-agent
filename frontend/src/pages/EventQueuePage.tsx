import { useEffect, useRef, useState, useMemo, useCallback } from "react"
import { Table, Tag, Button, Drawer, Form, Input, Select, message, Space, Typography, Badge, Progress } from "antd"
import { PlusOutlined, EyeOutlined } from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import { getEvents, submitEvent, getSseToken } from "../api/client"
import { useAuth } from "../context/AuthContext"
import { formatBeijingFull } from "../utils/time"
import { sseBaseUrl } from "../utils/sseBaseUrl"
import type { EventRecord } from "../types"

const STATUS_COLORS: Record<string, string> = { processing: "processing", completed: "success", pending_approval: "warning", ignored: "default", error: "error", rejected: "error" }
const PRIORITY_COLORS: Record<string, string> = { high: "red", medium: "orange", low: "default" }
const VERDICT_COLORS: Record<string, string> = { true_positive: "red", false_positive: "green", ignored: "default" }

export default function EventQueuePage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [events, setEvents] = useState<EventRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [filters, setFilters] = useState<{ status?: string; verdict?: string; priority?: string }>({})
  const [form] = Form.useForm()
  const intervalRef = useRef<ReturnType<typeof setInterval>>()

  const canSubmit = user?.role === "admin" || user?.role === "analyst"

  // V13 P2-24: keep the latest filters in a ref so the SSE handler (and the
  // mount-only effect) always fetch with current filters, and guard fetches
  // with a request sequence so a slow SSE-triggered response can never
  // overwrite a newer filtered fetch.
  const filtersRef = useRef(filters)
  useEffect(() => { filtersRef.current = filters }, [filters])
  const fetchSeq = useRef(0)

  const fetchEvents = useCallback(async () => {
    const seq = ++fetchSeq.current
    try {
      const data = await getEvents(filtersRef.current)
      if (seq !== fetchSeq.current) return // stale response, drop it
      setEvents(data.items); setTotal(data.total)
    } catch { /* ignore */ }
    finally { if (seq === fetchSeq.current) setLoading(false) }
  }, [])

  // V13 P2-24: the SSE subscription is mount-only (deps [fetchEvents]) --
  // filter changes re-fetch via the separate effect below instead of
  // tearing down and re-minting the EventSource (previously a filter
  // switch = disconnect storm + token re-mint on every change).
  useEffect(() => {
    fetchEvents()
    // F2 (2026-07-21): mint a 60s scoped token first so the long-lived
    // JWT never lands in the EventSource URL (nginx access log / browser
    // history / Referer). See getSseToken() in api/client.ts.
    if (!localStorage.getItem("token")) return
    let es: EventSource | null = null
    let cancelled = false
    ;(async () => {
      try {
        const shortToken = await getSseToken("events_list")
        if (cancelled) return
        const base = sseBaseUrl()
        // base 已含 /api/v1，只拼 /events/stream（不能重复 /api/v1，否则 404 致
        // EventSource 无限重连占满连接数致所有请求阻塞）。
        es = new EventSource(`${base}/events/stream?token=${shortToken}`)
        // 竞态兜底：创建后若已取消（用户快速离开），立即关闭，避免泄漏。
        if (cancelled) { es.close(); es = null; return }
        wireEs(es)
      } catch (err) { console.warn("event_queue_sse_token_failed", err) }
    })()
    function wireEs(es: EventSource) {
    es.onmessage = () => {
      // The server emits `{type, event_id, ...}` on every event update;
      // we don't care about the payload -- just refetch the list.
      fetchEvents()
    }
    // 防重连风暴：404/网络错误 readyState=CLOSED 时主动 close，避免无限重连
    // 占满浏览器同域连接数致所有请求阻塞。
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) es.close()
    }
    }
    return () => {
      cancelled = true
      if (es) { es.close(); es = null }
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchEvents])

  // V13 P2-24: filter changes re-fetch the list without touching the SSE.
  useEffect(() => {
    fetchEvents()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters])

  // V12 阶段 3.2: memoize columns
  const columns = useMemo(() => [
    { title: "时间", dataIndex: "submitted_at", key: "submitted_at", width: 180, render: (v: string) => formatBeijingFull(v) },
    { title: "来源", dataIndex: "source", key: "source", width: 80 },
    { title: "定级", dataIndex: "priority", key: "priority", width: 70, render: (v: string) => v ? <Tag color={PRIORITY_COLORS[v] || "default"}>{v}</Tag> : "-" },
    { title: "结论", dataIndex: "final_verdict", key: "final_verdict", width: 110, render: (v: string) => v ? <Tag color={VERDICT_COLORS[v] || "default"}>{v}</Tag> : "-" },
    { title: "置信度", dataIndex: "confidence", key: "confidence", width: 120, render: (v: number | null) => v != null ? <Progress percent={Math.round(v * 100)} size="small" /> : "-" },
    { title: "状态", dataIndex: "status", key: "status", width: 120, render: (v: string) => <Badge status={(STATUS_COLORS[v] || "default") as import("antd").BadgeProps["status"]} text={v} /> },
    { title: "耗时", dataIndex: "duration_ms", key: "duration_ms", width: 70, render: (v: number | null) => v ? `${v}ms` : "-" },
    { title: "操作", key: "actions", width: 100, render: (_: any, r: EventRecord) => <Button size="small" icon={<EyeOutlined />} onClick={() => navigate(`/events/${r.event_id}`)}>轨迹</Button> },
  ], [])

  return (
    <div>
      <Space style={{ marginBottom: 16, justifyContent: "space-between", width: "100%" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>事件队列</Typography.Title>
        <Space>
          <Select allowClear placeholder="状态" style={{ width: 130 }} onChange={(v) => setFilters(f => ({ ...f, status: v }))} options={["processing", "completed", "pending_approval", "ignored", "error", "rejected"].map(s => ({ value: s, label: s }))} />
          <Select allowClear placeholder="结论" style={{ width: 130 }} onChange={(v) => setFilters(f => ({ ...f, verdict: v }))} options={["true_positive", "false_positive", "ignored"].map(s => ({ value: s, label: s }))} />
          <Select allowClear placeholder="定级" style={{ width: 110 }} onChange={(v) => setFilters(f => ({ ...f, priority: v }))} options={["high", "medium", "low"].map(s => ({ value: s, label: s }))} />
          {canSubmit && <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawerOpen(true)}>提交新事件</Button>}
        </Space>
      </Space>

      <Table dataSource={events} columns={columns} rowKey="event_id" loading={loading} pagination={{ defaultPageSize: 20, total, showSizeChanger: true, pageSizeOptions: ["20", "50", "100"], showTotal: (t) => `共 ${t} 个事件` }} size="small" />

      <Drawer title="提交新事件" open={drawerOpen} onClose={() => setDrawerOpen(false)} width={500}>
        <Form form={form} layout="vertical" onFinish={async (values) => {
          setSubmitting(true)
          try {
            const iocs: Record<string, string[]> = {}
            if (values.ips) iocs.ip = values.ips.split(",").map((s: string) => s.trim())
            if (values.domains) iocs.domains = values.domains.split(",").map((s: string) => s.trim())
            await submitEvent(values.sanitized_text, iocs, values.source, true)
            message.success("事件已提交")
            setDrawerOpen(false); form.resetFields(); fetchEvents()
          } catch (err: any) { message.error(err.response?.data?.detail || "提交失败") }
          finally { setSubmitting(false) }
        }}>
          <Form.Item name="sanitized_text" label="事件描述" rules={[{ required: true }]}>
            <Input.TextArea rows={4} placeholder='例如: Honeypot captured whoami from 45.33.32.156' />
          </Form.Item>
          <Form.Item name="source" label="来源" initialValue="api">
            <Select options={[{ value: "api", label: "API" }, { value: "honeypot", label: "蜜罐" }, { value: "waf", label: "WAF" }, { value: "ids", label: "IDS" }, { value: "edr", label: "EDR" }]} />
          </Form.Item>
          <Form.Item name="ips" label="IOC IP（逗号分隔）"><Input placeholder="203.0.113.5, 198.51.100.2" /></Form.Item>
          <Form.Item name="domains" label="IOC 域名（逗号分隔）"><Input placeholder="evil.com" /></Form.Item>
          <Button type="primary" htmlType="submit" loading={submitting} block>提交并运行研判</Button>
        </Form>
      </Drawer>
    </div>
  )
}
