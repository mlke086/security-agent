import { useState } from "react"
import { Card, Table, Tag, Select, Button, Space, message, Modal } from "antd"
import { ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined } from "@ant-design/icons"
import api from "../api/client"

interface Finding {
  finding_id: string; hostname: string; cve: string | null; name: string;
  severity: string; ai_severity: string | null; ai_filtered: boolean;
  status: string; detected_at: string; category: string; fix_advice: string | null;
}

const SEV_COLORS: Record<string, string> = { critical: "red", high: "orange", medium: "gold", low: "green", info: "blue" }
const STATUS_ACTIONS = [
  { label: "Open", value: "open", color: "red", icon: <CloseCircleOutlined /> },
  { label: "Fixed", value: "fixed", color: "green", icon: <CheckCircleOutlined /> },
  { label: "Accepted", value: "accepted", color: "blue", icon: <CheckCircleOutlined /> },
]

export default function VulnListPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [filterSev, setFilterSev] = useState<string | undefined>()
  const [filterStatus, setFilterStatus] = useState<string | undefined>()
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [batchModal, setBatchModal] = useState(false)

  const fetchData = async () => {
    setLoading(true)
    try {
      const params: any = {}
      if (filterSev) params.severity = filterSev
      if (filterStatus) params.status = filterStatus
      const res = await api.get("/vulnscan/results", { params })
      setFindings(res.data.items)
    } catch { message.error("Failed to load") }
    finally { setLoading(false) }
  }

  const updateStatus = async (id: string, newStatus: string) => {
    try {
      await api.patch("/vulnscan/vulns/" + id, { status: newStatus })
      message.success("Status updated")
      fetchData()
    } catch { message.error("Update failed") }
  }

  const batchUpdateStatus = async (newStatus: string) => {
    setBatchModal(false)
    for (const id of selectedKeys) {
      try { await api.patch("/vulnscan/vulns/" + id, { status: newStatus }) }
      catch { /* continue */ }
    }
    message.success("Batch update done")
    setSelectedKeys([])
    fetchData()
  }

  const columns = [
    { title: "Host", dataIndex: "hostname", key: "hostname", width: 110 },
    { title: "CVE", dataIndex: "cve", key: "cve", width: 140, render: (v: string | null) => v || "-" },
    { title: "Name", dataIndex: "name", key: "name", ellipsis: true },
    { title: "Severity", dataIndex: "severity", key: "severity", width: 90, render: (v: string) => <Tag color={SEV_COLORS[v]}>{v}</Tag> },
    { title: "AI Level", dataIndex: "ai_severity", key: "ai_severity", width: 90, render: (v: string | null) => v ? <Tag color={SEV_COLORS[v]}>{v}</Tag> : "-" },
    { title: "AI Verdict", dataIndex: "ai_filtered", key: "ai_filtered", width: 90, render: (v: boolean) => v ? <Tag color="default">False Positive</Tag> : null },
    {
      title: "Status", dataIndex: "status", key: "status", width: 130,
      render: (v: string, record: Finding) => (
        <Select
          value={v}
          size="small"
          style={{ width: 110 }}
          onChange={(newVal) => updateStatus(record.finding_id, newVal)}
          options={STATUS_ACTIONS.map(a => ({
            label: <span>{a.icon} {a.label}</span>,
            value: a.value,
          }))}
        />
      ),
    },
    { title: "Detected", dataIndex: "detected_at", key: "detected_at", width: 160, render: (v: string) => v?.slice(0, 19) || "-" },
  ]

  return (
    <Card
      title="Vulnerability List"
      extra={
        <Space>
          <Select placeholder="Severity" allowClear style={{ width: 110 }} onChange={setFilterSev}
            options={["critical", "high", "medium", "low", "info"].map(s => ({ label: s, value: s }))} />
          <Select placeholder="Status" allowClear style={{ width: 110 }} onChange={setFilterStatus}
            options={["open", "fixed", "accepted"].map(s => ({ label: s, value: s }))} />
          <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>Refresh</Button>
          {selectedKeys.length > 0 && (
            <Button type="primary" size="small" onClick={() => setBatchModal(true)}>
              Batch ({selectedKeys.length})
            </Button>
          )}
        </Space>
      }
    >
      <Table
        dataSource={findings}
        columns={columns}
        rowKey="finding_id"
        loading={loading}
        rowSelection={{
          selectedRowKeys: selectedKeys,
          onChange: (keys) => setSelectedKeys(keys as string[]),
        }}
        pagination={{ pageSize: 20 }}
        locale={{ emptyText: "No vulnerability records. Run a scan first." }}
      />

      <Modal open={batchModal} title="Batch Update Status" onCancel={() => setBatchModal(false)} footer={null}>
        <p>Update {selectedKeys.length} findings to:</p>
        <Space direction="vertical" style={{ width: "100%" }}>
          {STATUS_ACTIONS.map(a => (
            <Button key={a.value} block onClick={() => batchUpdateStatus(a.value)}>
              {a.icon} {a.label}
            </Button>
          ))}
        </Space>
      </Modal>
    </Card>
  )
}
