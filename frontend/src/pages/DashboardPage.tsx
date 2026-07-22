import { useEffect, useRef, useState } from "react"
import { Card, Row, Col, Statistic, Typography, Spin, Empty } from "antd"
import { AlertOutlined, CheckCircleOutlined, ClockCircleOutlined, ThunderboltOutlined } from "@ant-design/icons"
import { Pie, Column, Line } from "@ant-design/charts"
import api, { getMetrics, getMetricsTimeline, getSseToken } from "../api/client"
import type { Metrics, TimelinePoint } from "../types"

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [loading, setLoading] = useState(true)
  const sseRef = useRef<EventSource | null>(null)

  const fetchData = async () => {
    try {
      setMetrics(await getMetrics())
      setTimeline((await getMetricsTimeline()).timeline)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  useEffect(() => {
    fetchData()
    // F2 (2026-07-21): exchange the long-lived JWT for a 60s scoped SSE
    // token; reuse api.defaults.baseURL so reverse-proxy / k8s ingress
    // still work. Without this, the long-lived JWT leaks into nginx
    // access logs and browser history, and the EventSource keeps
    // reconnecting forever once the JWT expires (no refresh path).
    if (!localStorage.getItem("token")) return  // P2-FE-07 guard
    let cancelled = false
    ;(async () => {
      try {
        const shortToken = await getSseToken("metrics")
        if (cancelled) return
        const base = (api.defaults.baseURL || "").replace(/\/+$/, "")
        // base 已含 /api/v1，只拼 /metrics/stream（不能重复 /api/v1，否则 404
        // 致 EventSource 无限重连，占满浏览器同域连接数致所有请求阻塞）。
        const source = new EventSource(`${base}/metrics/stream?token=${shortToken}`)
        // 立即存 ref，确保 cleanup（即便快速离开页面）也能 close，避免泄漏。
        sseRef.current = source
        source.onmessage = (e) => { if (e.data && e.data !== ": heartbeat") fetchData() }
        // 防止 EventSource 重连风暴：404/网络错误后 readyState=CLOSED，
        // 浏览器会无限重连占满同域连接数（6个）致所有请求阻塞。CLOSED 时主动 close。
        source.onerror = () => {
          if (source && source.readyState === EventSource.CLOSED) {
            source.close()
            if (sseRef.current === source) sseRef.current = null
          }
        }
      } catch (err) { console.warn("dashboard_sse_token_failed", err) }
    })()
    return () => {
      cancelled = true
      if (sseRef.current) { sseRef.current.close(); sseRef.current = null }
    }
  }, [])

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />

  const verdictData = Object.entries(metrics?.by_verdict || {}).map(([k, v]) => ({ type: k, value: v }))
  const priorityData = Object.entries(metrics?.by_priority || {}).map(([k, v]) => ({ type: k, value: v }))
  const total = metrics?.total_events || 0

  return (
    <div>
      <Typography.Title level={4}>运营大屏</Typography.Title>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={6}><Card><Statistic title="总事件数" value={total} prefix={<AlertOutlined />} /></Card></Col>
        <Col span={6}><Card><Statistic title="真阳性" value={metrics?.by_verdict?.true_positive || 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: "#52c41a" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="待审批" value={metrics?.pending_approvals || 0} prefix={<ClockCircleOutlined />} valueStyle={{ color: "#faad14" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="平均耗时" value={metrics?.avg_duration_ms || 0} suffix="ms" prefix={<ThunderboltOutlined />} /></Card></Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col span={12}>
          <Card title="结论分布" size="small">
            {verdictData.length === 0 ? <Empty description="暂无数据" /> : (
              <Pie {...{
                data: verdictData, angleField: "value", colorField: "type", radius: 0.8,
                label: { type: "outer", content: "{name} ({percentage})" },
                interactions: [{ type: "element-active" }],
                height: 280,
              }} />
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="定级分布" size="small">
            {priorityData.length === 0 ? <Empty description="暂无数据" /> : (
              <Column {...{
                data: priorityData, xField: "type", yField: "value",
                color: ({ type }: any) => type === "high" ? "#ff4d4f" : type === "medium" ? "#faad14" : "#52c41a",
                height: 280,
              }} />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={24}>
          <Card title="事件趋势（按小时）" size="small">
            {timeline.length === 0 ? <Empty description="暂无数据" /> : (
              <Line {...{
                data: timeline, xField: "time", yField: "total",
                point: { size: 3, shape: "circle" },
                height: 280,
              }} />
            )}
          </Card>
        </Col>
      </Row>

      <Typography.Text type="secondary" style={{ display: "block", marginTop: 16, textAlign: "right", fontSize: 12 }}>
        SSE 实时推送
      </Typography.Text>
    </div>
  )
}
