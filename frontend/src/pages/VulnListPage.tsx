import { useEffect, useState } from "react"
import { Card, Table, Tag, Select, Button, Space, message, Modal } from "antd"
import { ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined } from "@ant-design/icons"
import api from "../api/client"

interface Finding {
  finding_id: string; hostname: string; cve: string | null; name: string;
  severity: string; ai_severity: string | null; ai_filtered: boolean;
  status: string; detected_at: string; category: string; fix_advice: string | null;
}

const SEV_COLORS: Record<string, string> = { critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue" }
const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" }
const STATUS_ACTIONS = [
  { label: "待修复", value: "open", color: "red", icon: <CloseCircleOutlined /> },
  { label: "已修复", value: "fixed", color: "green", icon: <CheckCircleOutlined /> },
  { label: "已接受", value: "accepted", color: "blue", icon: <CheckCircleOutlined /> },
]

export default function VulnListPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [filterSev, setFilterSev] = useState<string | undefined>()
  const [filterStatus, setFilterStatus] = useState<string | undefined>()
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [batchModal, setBatchModal] = useState(false)

  // P1-FE-03 (2026-07-20): fetch on mount so the page doesn't show an
  // empty table until the user clicks "Refresh".
  useEffect(() => { fetchData() }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const params: any = {}
      if (filterSev) params.severity = filterSev
      if (filterStatus) params.status = filterStatus
      const res = await api.get("/vulnscan/results", { params })
      setFindings(res.data.items)
    } catch { message.error("加载失败") }
    finally { setLoading(false) }
  }

  const updateStatus = async (id: string, newStatus: string) => {
    try {
      await api.patch("/vulnscan/vulns/" + id, { status: newStatus })
      message.success("状态已更新")
      fetchData()
    } catch { message.error("更新失败") }
  }

  const batchUpdateStatus = async (newStatus: string) => {
    setBatchModal(false)
    for (const id of selectedKeys) {
      try { await api.patch("/vulnscan/vulns/" + id, { status: newStatus }) }
      catch { /* continue */ }
    }
    message.success("批量更新完成")
    setSelectedKeys([])
    fetchData()
  }

  const columns = [
    { title: "主机", dataIndex: "hostname", key: "hostname", width: 110 },
    { title: "CVE", dataIndex: "cve", key: "cve", width: 140, render: (v: string | null) => v || "-" },
    { title: "名称", dataIndex: "name", key: "name", ellipsis: true },
    { title: "严重等级", dataIndex: "severity", key: "severity", width: 90, render: (v: string) => <Tag color={SEV_COLORS[v]}>{SEV_LABEL[v] || v}</Tag> },
    { title: "AI 等级", dataIndex: "ai_severity", key: "ai_severity", width: 90, render: (v: string | null) => v ? <Tag color={SEV_COLORS[v]}>{SEV_LABEL[v] || v}</Tag> : "-" },
    { title: "AI 判定", dataIndex: "ai_filtered", key: "ai_filtered", width: 90, render: (v: boolean) => v ? <Tag color="default">误报</Tag> : null },
    {
      title: "状态", dataIndex: "status", key: "status", width: 130,
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
    { title: "发现时间", dataIndex: "detected_at", key: "detected_at", width: 160, render: (v: string) => v?.slice(0, 19) || "-" },
  ]

  return (
    <Card
      title="漏洞清单"
      extra={
        <Space>
          <Select placeholder="严重等级" allowClear style={{ width: 110 }} onChange={setFilterSev}
            options={Object.entries(SEV_LABEL).map(([k, v]) => ({ label: v, value: k }))} />
          <Select placeholder="状态" allowClear style={{ width: 110 }} onChange={setFilterStatus}
            options={STATUS_ACTIONS.map(a => ({ label: a.label, value: a.value }))} />
          <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>刷新</Button>
          {selectedKeys.length > 0 && (
            <Button type="primary" size="small" onClick={() => setBatchModal(true)}>
              批量处理 ({selectedKeys.length})
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
        locale={{ emptyText: "暂无漏洞记录，请先执行扫描" }}
      />

      <Modal open={batchModal} title="批量更新状态" onCancel={() => setBatchModal(false)} footer={null}>
        <p>将 {selectedKeys.length} 条漏洞更新为：</p>
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
