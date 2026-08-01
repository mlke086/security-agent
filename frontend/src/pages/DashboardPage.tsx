import { useEffect, useRef, useState } from "react"
import { sseBaseUrl } from "../utils/sseBaseUrl"
import { Card, Row, Col, Statistic, Typography, Spin, Empty, Progress, Tag } from "antd"
import { AlertOutlined, CheckCircleOutlined, ClockCircleOutlined, ThunderboltOutlined } from "@ant-design/icons"
import { getMetrics, getMetricsTimeline, getSseToken } from "../api/client"
import type { Metrics, TimelinePoint } from "../types"
import "./DashboardPage.css"

// 结论/定级中文标签 + 颜色
const VERDICT_LABEL: Record<string, string> = {
  true_positive: "真阳性", false_positive: "假阳性", unknown: "未知", ignored: "已忽略",
}
const VERDICT_COLOR: Record<string, string> = {
  true_positive: "#52c41a", false_positive: "#ff4d4f", unknown: "#faad14", ignored: "#d9d9d9",
}
const PRIORITY_LABEL: Record<string, string> = {
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示",
}
const PRIORITY_COLOR: Record<string, string> = {
  critical: "#cf1322", high: "#d4380d", medium: "#d4b106", low: "#389e0d", info: "#1677ff",
}

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [loading, setLoading] = useState(true)
  // 首屏生长动画：数据首次到位后从 0 长到真实值（仅一次）；后续 SSE 更新靠
  // CSS width 过渡平滑伸缩，不再重放生长。
  const [animDone, setAnimDone] = useState(false)
  const sseRef = useRef<EventSource | null>(null)

  const fetchData = async () => {
    try {
      setMetrics(await getMetrics())
      setTimeline((await getMetricsTimeline()).timeline)
    } catch (err) {
      // S-P2-19 (V12): a failed initial load used to leave a blank page
      // with no signal. Log it so operators can see the dashboard is
      // showing stale/empty data rather than silently hiding the failure.
      console.warn("dashboard_metrics_load_failed", err)
    } finally { setLoading(false) }
  }

  useEffect(() => {
    fetchData()
    if (!localStorage.getItem("token")) return
    let cancelled = false
    ;(async () => {
      try {
        const shortToken = await getSseToken("metrics")
        if (cancelled) return
        const base = sseBaseUrl()
        const source = new EventSource(`${base}/metrics/stream?token=${shortToken}`)
        sseRef.current = source
        source.onmessage = (e) => { if (e.data && e.data !== ": heartbeat") fetchData() }
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

  // 首次数据到位后触发一次生长动画（0 -> 真实值）。
  useEffect(() => {
    if (!loading && !animDone) {
      const t = setTimeout(() => setAnimDone(true), 60)
      return () => clearTimeout(t)
    }
  }, [loading, animDone])

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />

  // V12 阶段 3.3: by_verdict/by_priority 已是 {[key: string]: number}，去掉冗余 as number
  const verdictData = Object.entries(metrics?.by_verdict || {}).map(([k, v]) => ({ type: k, value: v }))
  const priorityData = Object.entries(metrics?.by_priority || {}).map(([k, v]) => ({ type: k, value: v }))
  const total = metrics?.total_events || 0

  // 趋势最大值（用于 Progress 比例）
  const timelineMax = timeline.length > 0 ? Math.max(...timeline.map((t) => t.total || 0), 1) : 1

  return (
    <div>
      <Typography.Title level={4}>态势感知</Typography.Title>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }} className="dash-fade-in">
        <Col span={6}><Card className="dash-stat-card"><Statistic title="总事件数" value={total} prefix={<AlertOutlined />} /></Card></Col>
        <Col span={6}><Card className="dash-stat-card"><Statistic title="真阳性" value={metrics?.by_verdict?.true_positive || 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: "#52c41a" }} /></Card></Col>
        <Col span={6}><Card className="dash-stat-card"><Statistic title="待审批" value={metrics?.pending_approvals || 0} prefix={<ClockCircleOutlined />} valueStyle={{ color: "#faad14" }} /></Card></Col>
        <Col span={6}><Card className="dash-stat-card"><Statistic title="平均耗时" value={metrics?.avg_duration_ms || 0} suffix="ms" prefix={<ThunderboltOutlined />} /></Card></Col>
      </Row>

      <Row gutter={[16, 16]} className="dash-fade-in">
        <Col span={12}>
          <Card title="结论分布" size="small">
            {verdictData.length === 0 ? <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} /> : (
              <div className="dash-bar dash-bar-thick" style={{ padding: "16px 0" }}>
                {verdictData.map((d) => {
                  const pct = total > 0 ? Math.round((d.value / total) * 100) : 0
                  return (
                    <div key={d.type} style={{ marginBottom: 20 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <span><Tag color={VERDICT_COLOR[d.type] || "default"} style={{ fontSize: 13, padding: "2px 10px" }}>{VERDICT_LABEL[d.type] || d.type}</Tag></span>
                        <span><span className="dash-value">{d.value}</span> <span className="dash-pct">({pct}%)</span></span>
                      </div>
                      <Progress percent={animDone ? pct : 0} strokeWidth={22} strokeColor={VERDICT_COLOR[d.type] || "#1677ff"} showInfo={false} />
                    </div>
                  )
                })}
              </div>
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="定级分布" size="small">
            {priorityData.length === 0 ? <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} /> : (
              <div className="dash-bar dash-bar-thick" style={{ padding: "16px 0" }}>
                {priorityData.map((d) => {
                  const maxVal = Math.max(...priorityData.map((x) => x.value), 1)
                  const pct = Math.round((d.value / maxVal) * 100)
                  return (
                    <div key={d.type} style={{ marginBottom: 20 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <span><Tag color={PRIORITY_COLOR[d.type] || "default"} style={{ fontSize: 13, padding: "2px 10px" }}>{PRIORITY_LABEL[d.type] || d.type}</Tag></span>
                        <span className="dash-value">{d.value}</span>
                      </div>
                      <Progress percent={animDone ? pct : 0} strokeWidth={22} strokeColor={PRIORITY_COLOR[d.type] || "#1677ff"} showInfo={false} />
                    </div>
                  )
                })}
              </div>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }} className="dash-fade-in">
        <Col span={24}>
          <Card title="事件趋势（按小时）" size="small">
            {timeline.length === 0 ? <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} /> : (
              <div className="dash-bar" style={{ maxHeight: 320, overflow: "auto", padding: "8px 0" }}>
                {timeline.slice().reverse().map((t, i) => (
                  <div key={i} className="dash-trend-row" style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4, fontSize: 13 }}>
                    <span className="dash-time" style={{ width: 120, color: "#999", flexShrink: 0 }}>{t.time}</span>
                    <Progress
                      percent={animDone ? Math.round(((t.total || 0) / timelineMax) * 100) : 0}
                      strokeWidth={16}
                      strokeColor="#1677ff"
                      showInfo={false}
                      style={{ flex: 1, marginRight: 0 }}
                    />
                    <span style={{ width: 44, textAlign: "right", flexShrink: 0, fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>{t.total}</span>
                  </div>
                ))}
              </div>
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
