import { useState, useEffect, useRef } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { Card, Progress, Tag, Descriptions, Button, Space, Spin, message } from "antd"
import { ArrowLeftOutlined, CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined, SyncOutlined, FileTextOutlined, DownloadOutlined } from "@ant-design/icons"
import api, { getSseToken } from "../api/client"

const SEV_COLOR: Record<string, string> = { critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue" }
const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" }

export default function ScanMonitorPage() {
  const { taskId } = useParams<{ taskId: string }>()
  const navigate = useNavigate()
  const [task, setTask] = useState<any>(null)
  const [events, setEvents] = useState<any[]>([])
  const [findings, setFindings] = useState<any[]>([])
  const [downloading, setDownloading] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)
  const lastRefreshRef = useRef<number>(0)
  const doneRef = useRef<boolean>(false)  // SSE 收到 task_done(正常结束)标记

  const refreshTask = async () => {
    if (!taskId) return
    try {
      const r = await api.get(`/vulnscan/tasks/${taskId}`)
      setTask(r.data)
      // 已完成/失败的任务无新 SSE 事件，拉取 findings 展示扫描结果摘要
      if (r.data.status === "completed" || r.data.status === "failed") {
        try {
          const fr = await api.get(`/vulnscan/results`, { params: { task_id: taskId } })
          setFindings(fr.data.items || [])
        } catch { /* findings 拉取失败不阻断 */ }
      }
    } catch { /* 任务可能尚未写入 ES，忽略 */ }
  }

  useEffect(() => {
    if (!taskId) return
    doneRef.current = false  // 重置正常结束标记
    refreshTask()

    // P2-FE-10 (2026-07-20): rely on SSE for live updates; keep only the
    // initial one-shot fetch. The previous version also polled every 3s,
    // which duplicated the SSE traffic and wasted cycles.
    // P2-FE-07: skip when no token.
    if (!localStorage.getItem("token")) {
      console.warn("scan_monitor_no_token_skipping_sse")
      return
    }
    // F2 (2026-07-21): mint a 60s scoped SSE token first; reuse the
    // configured baseURL so reverse-proxy / k8s ingress keep working.
    let cancelled = false
    ;(async () => {
      try {
        const shortToken = await getSseToken("events")
        // 用户已离开（cleanup 置 cancelled）则不再创建 EventSource，避免泄漏。
        if (cancelled) return
        const base = (api.defaults.baseURL || "").replace(/\/+$/, "")
        const source = new EventSource(`${base}/vulnscan/tasks/${taskId}/stream?token=${shortToken}`)
        // 立即存 ref，确保 cleanup（即便在 onmessage 绑定前）也能 close，
        // 避免快速进出监控页时 EventSource 未被关闭累积泄漏，占满浏览器
        // 同域 6 连接数致所有请求阻塞（status=0，30s timeout）。
        eventSourceRef.current = source
        wireEs(source)
      } catch (err) { console.warn("scan_monitor_sse_token_failed", err) }
    })()
    function wireEs(es: EventSource) {
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        const inner = data.channel
          ? (typeof data.data === "string" ? JSON.parse(data.data) : data.data)
          : data
        // 后端任务终态时推送 task_done 后主动关闭连接（正常结束），
        // 标记之，避免 onerror 误弹"连接已断开"提示。
        if (inner.type === "task_done" || inner.status === "completed" || inner.status === "failed") {
          doneRef.current = true
        }
        setEvents(prev => [...prev, { ...inner, ts: Date.now() }].slice(-50))

        // 需求6：SSE 事件到达时，防抖刷新任务状态（最多 3s 一次），
        // 让顶部状态 Tag / 进度条随扫描进度实时更新（此前 setTask 只在首次 fetch 调用，
        // 导致扫描过程中状态不刷新）。
        const now = Date.now()
        if (now - lastRefreshRef.current > 3000) {
          lastRefreshRef.current = now
          refreshTask()
        }

        // 收到完成/失败类事件时立即刷新一次，确保最终状态及时同步
        const evType = (inner.type || inner.step || "").toString()
        if (evType.includes("complete") || evType.includes("finish") || evType.includes("fail") || inner.status === "completed" || inner.status === "failed") {
          lastRefreshRef.current = now
          refreshTask()
        }
      } catch {}
    }
    // P2-FE-06 (2026-07-20): the previous version closed the EventSource on
    // every error, permanently killing the auto-reconnect. Let the
    // EventSource reconnect itself on transient errors; only intervene if
    // the server explicitly returned 401 (token invalid).
    // onerror：区分「正常结束」(收到 task_done)与「异常断开」(404/网络错误)。
    // 正常结束不提示；异常断开才提示，且不跳登录(真401由axios拦截器处理)。
    let errCount = 0
    es.onerror = () => {
      errCount += 1
      if (es.readyState === EventSource.CLOSED || errCount >= 3) {
        es.close()
        if (eventSourceRef.current === es) eventSourceRef.current = null
        // 收到 task_done 的正常结束不弹提示
        if (!doneRef.current) {
          message.warning("实时连接已断开，可刷新页面重试")
        }
      }
    }
    }

    // useEffect cleanup（修复：原 return 在 wireEs 内部被丢弃，EventSource 永不关闭）
    return () => {
      cancelled = true
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
    }
  }, [taskId])

  const done = task?.stats?.done || 0
  const total = task?.stats?.total || 0
  const pct = total ? Math.round((done / total) * 100) : 0
  const isCompleted = task?.status === "completed"
  const isFailed = task?.status === "failed"

  const statusConfig: any = {
    queued: { color: "default", icon: <ClockCircleOutlined /> },
    dispatching: { color: "processing", icon: <SyncOutlined spin /> },
    scanning: { color: "processing", icon: <SyncOutlined spin /> },
    analyzing: { color: "processing", icon: <ClockCircleOutlined /> },
    completed: { color: "success", icon: <CheckCircleOutlined /> },
    failed: { color: "error", icon: <ExclamationCircleOutlined /> },
  }
  const sc = statusConfig[task?.status] || { color: "default" }

  const statusLabel: Record<string, string> = {
    queued: "排队中", dispatching: "下发中", scanning: "扫描中",
    analyzing: "分析中", completed: "已完成", failed: "失败",
  }

  const handleDownload = async () => {
    if (!taskId) return
    setDownloading(true)
    try {
      const res = await api.get(`/vulnscan/reports/${taskId}/export`, {
        params: { format: "html" },
        responseType: "blob",
      })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: "text/html" }))
      const a = document.createElement("a")
      a.href = url
      a.download = `scan-report-${taskId}.html`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch {
      message.error("下载报告失败，任务可能尚未生成报告")
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>返回</Button>
        {isCompleted && (
          <>
            <Button type="primary" icon={<FileTextOutlined />} onClick={() => navigate(`/report?taskId=${taskId}`)}>查看报告</Button>
            <Button icon={<DownloadOutlined />} loading={downloading} onClick={handleDownload}>下载报告</Button>
          </>
        )}
      </Space>

      <Card title="扫描监控">
        <Descriptions column={3} size="small" bordered>
          <Descriptions.Item label="任务ID">{taskId}</Descriptions.Item>
          <Descriptions.Item label="状态"><Tag color={sc.color} icon={sc.icon}>{statusLabel[task?.status] || task?.status || "-"}</Tag></Descriptions.Item>
          <Descriptions.Item label="进度">{done}/{total}</Descriptions.Item>
        </Descriptions>
        {total > 0 && <Progress percent={pct} status={isFailed ? "exception" : isCompleted ? "success" : "active"} style={{ marginTop: 16 }} />}

        <Card title={isCompleted || isFailed ? "扫描结果" : "实时事件"} size="small" style={{ marginTop: 16 }}>
          <div style={{ maxHeight: 400, overflow: "auto" }}>
            {(isCompleted || isFailed) ? (
              findings.length === 0 ? (
                <div style={{ color: "#999", padding: 20, textAlign: "center" }}>
                  {isFailed ? "任务失败，无扫描结果" : "未发现漏洞"}
                </div>
              ) : (
                findings.map((f, i) => (
                  <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid #f0f0f0", fontSize: 12 }}>
                    <Tag color={SEV_COLOR[f.severity] || "default"}>{SEV_LABEL[f.severity] || f.severity}</Tag>
                    <span style={{ marginLeft: 8 }}>{f.cve ? `[${f.cve}] ` : ""}{f.name}</span>
                    <div style={{ color: "#999", marginTop: 2 }}>{f.evidence}</div>
                  </div>
                ))
              )
            ) : events.length === 0 ? (
              <div style={{ color: "#999", padding: 20, textAlign: "center" }}>
                <Spin size="small" />
                <div style={{ marginTop: 8 }}>任务进行中，等待 agent 上报扫描进度...</div>
              </div>
            ) : (
              [...events].reverse().map((ev, i) => (
                <div key={i} style={{ padding: "4px 0", borderBottom: "1px solid #f0f0f0", fontSize: 12, display: "flex", gap: 8 }}>
                  <span style={{ color: "#999" }}>{new Date(ev.ts).toLocaleTimeString()}</span>
                  <Tag style={{ fontSize: 11 }}>{ev.type || ev.step || ""}</Tag>
                  <span>{ev.status || ev.message || ev.step || JSON.stringify(ev)}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </Card>
    </div>
  )
}
