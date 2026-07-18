import { useEffect, useState } from "react"
import { Table, Tag, Button, Typography, message, Space, Badge, Tooltip } from "antd"
import { CheckOutlined, CloseOutlined, EyeOutlined } from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import { getApprovals, approveEvent } from "../api/client"
import { useAuth } from "../context/AuthContext"
import type { Approval } from "../types"

export default function ApprovalsPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [items, setItems] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [operating, setOperating] = useState<string | null>(null)

  const canApprove = user?.role === "admin" || user?.role === "responder"

  const fetchData = async () => {
    try { const d = await getApprovals(); setItems(d.items) } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchData(); const iv = setInterval(fetchData, 5000); return () => clearInterval(iv) }, [])

  const handleAction = async (eventId: string, action: string) => {
    setOperating(eventId)
    try { await approveEvent(eventId, action); message.success(action === "approved" ? "已批准" : "已驳回"); fetchData() }
    catch { message.error("操作失败") }
    finally { setOperating(null) }
  }

  const levelColor: Record<string, string> = { L1: "default", L2: "blue", L3: "orange", L4: "red", L5: "red" }
  const statusColor: Record<string, string> = { pending: "warning", approved: "success", rejected: "error", timeout: "default" }

  const columns = [
    { title: "事件 ID", dataIndex: "event_id", key: "event_id", width: 180, render: (v: string) => <a onClick={() => navigate(`/events/${v}`)}>{v}</a> },
    { title: "操作等级", dataIndex: "operation_level", key: "operation_level", width: 90, render: (v: string) => <Tag color={levelColor[v] || "default"}>{v}</Tag> },
    { title: "状态", dataIndex: "status", key: "status", width: 80, render: (v: string) => <Badge status={statusColor[v] as any} text={v} /> },
    { title: "进度", key: "progress", width: 80, render: (_: any, r: Approval) => `${r.approvals?.length || 0} / ${r.required}` },
    { title: "创建时间", dataIndex: "created_at", key: "created_at", width: 160, render: (v: string) => v ? new Date(v).toLocaleString() : "-" },
    { title: "操作", key: "actions", width: 160, render: (_: any, r: Approval) => canApprove ? (
      <Space>
        <Button size="small" type="primary" icon={<CheckOutlined />} loading={operating === r.event_id} onClick={() => handleAction(r.event_id, "approved")}>通过</Button>
        <Button size="small" danger icon={<CloseOutlined />} loading={operating === r.event_id} onClick={() => handleAction(r.event_id, "rejected")}>驳回</Button>
        <Tooltip title="查看事件详情"><Button size="small" icon={<EyeOutlined />} onClick={() => navigate(`/events/${r.event_id}`)} /></Tooltip>
      </Space>
    ) : "—",
    }
  ]

  return (
    <div>
      <Typography.Title level={4}>待审批列表</Typography.Title>
      <Table dataSource={items} columns={columns} rowKey="approval_id" loading={loading} pagination={false} size="small" />
    </div>
  )
}