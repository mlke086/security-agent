import { useState, useEffect, useRef } from "react"
import { useParams } from "react-router-dom"
import { Card, Progress, Tag, Descriptions } from "antd"
import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined, SyncOutlined } from "@ant-design/icons"
import api from "../api/client"

export default function ScanMonitorPage() {
  const { taskId } = useParams<{ taskId: string }>()
  const [task, setTask] = useState<any>(null)
  const [events, setEvents] = useState<any[]>([])
  const eventSourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!taskId) return
    api.get(`/vulnscan/tasks/${taskId}`).then(r => setTask(r.data)).catch(() => {})

    const token = localStorage.getItem("token")
    const es = new EventSource(`/api/v1/vulnscan/tasks/${taskId}/stream?token=${token}`)
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.channel) {
          const inner = typeof data.data === "string" ? JSON.parse(data.data) : data.data
          setEvents(prev => [...prev, { ...inner, ts: Date.now() }].slice(-50))
        } else {
          setEvents(prev => [...prev, { ...data, ts: Date.now() }].slice(-50))
        }
      } catch {}
    }
    es.onerror = () => { es.close() }
    eventSourceRef.current = es

    const timer = setInterval(() => {
      api.get(`/vulnscan/tasks/${taskId}`).then(r => setTask(r.data)).catch(() => {})
    }, 3000)

    return () => { es.close(); clearInterval(timer) }
  }, [taskId])

  const done = task?.stats?.done || 0
  const total = task?.stats?.total || 0
  const pct = total ? Math.round((done / total) * 100) : 0

  const statusConfig: any = {
    scanning: { color: "processing", icon: <SyncOutlined spin /> },
    analyzing: { color: "processing", icon: <ClockCircleOutlined /> },
    completed: { color: "success", icon: <CheckCircleOutlined /> },
    failed: { color: "error", icon: <ExclamationCircleOutlined /> },
  }
  const sc = statusConfig[task?.status] || { color: "default" }

  return (
    <div>
      <Card title={"扫描监控"}>
        <Descriptions column={3} size="small" bordered>
          <Descriptions.Item label="任务ID">{taskId}</Descriptions.Item>
          <Descriptions.Item label="状态"><Tag color={sc.color} icon={sc.icon}>{task?.status}</Tag></Descriptions.Item>
          <Descriptions.Item label="进度">{done}/{total}</Descriptions.Item>
        </Descriptions>
        {total > 0 && <Progress percent={pct} status={task?.status === "failed" ? "exception" : task?.status === "completed" ? "success" : "active"} style={{ marginTop: 16 }} />}

        <Card title="实时事件" size="small" style={{ marginTop: 16 }}>
          <div style={{ maxHeight: 400, overflow: "auto" }}>
            {events.length === 0 && <div style={{ color: "#999", padding: 20, textAlign: "center" }}>等待事件...</div>}
            {[...events].reverse().map((ev, i) => (
              <div key={i} style={{ padding: "4px 0", borderBottom: "1px solid #f0f0f0", fontSize: 12, display: "flex", gap: 8 }}>
                <span style={{ color: "#999" }}>{new Date(ev.ts).toLocaleTimeString()}</span>
                <Tag style={{ fontSize: 11 }}>{ev.type || ev.step || ""}</Tag>
                <span>{ev.status || ev.message || ev.step || JSON.stringify(ev)}</span>
              </div>
            ))}
          </div>
        </Card>
      </Card>
    </div>
  )
}
