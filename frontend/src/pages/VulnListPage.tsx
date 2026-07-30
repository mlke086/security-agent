import { useEffect, useState } from "react"
import { Card, Table, Tag, Select, Button, Space, message, Modal, Input, DatePicker, Tooltip } from "antd"
import { ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined, EyeOutlined, SearchOutlined } from "@ant-design/icons"
import api, { listVulns, getHostStats, type HostStatsRow, type VulnFinding } from "../api/client"
import { formatBeijing } from "../utils/time"
import { useDebouncedValue } from "../utils/useDebouncedValue"
import AiEvidenceBadge from "../components/AiEvidenceBadge"
import VulnDetailDrawer from "../components/VulnDetailDrawer"

const SEV_COLORS: Record<string, string> = { critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue" }
const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" }
const STATUS_ACTIONS = [
  { label: "待修复", value: "open", color: "red", icon: <CloseCircleOutlined /> },
  { label: "已修复", value: "fixed", color: "green", icon: <CheckCircleOutlined /> },
  { label: "已接受", value: "accepted", color: "blue", icon: <CheckCircleOutlined /> },
]

export default function VulnListPage() {
  const [findings, setFindings] = useState<VulnFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [filterSev, setFilterSev] = useState<string | undefined>()
  const [filterStatus, setFilterStatus] = useState<string | undefined>()
  const [filterCve, setFilterCve] = useState("")
  const [filterNameKw, setFilterNameKw] = useState("")
  const [filterHostKw, setFilterHostKw] = useState("")
  const [filterGroup, setFilterGroup] = useState<string | undefined>()
  const [filterAiOnly, setFilterAiOnly] = useState<"all" | "ai" | "pending">("all")
  const [dateRange, setDateRange] = useState<[string, string] | null>(null)
  const [hostStats, setHostStats] = useState<HostStatsRow[]>([])
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  // V10 3.1 (2026-07-30): 300ms debounce on the three free-text
  // filters so each keystroke does not fire its own GET /vulnscan.
  // The input state stays immediate for snappy UI; the network
  // call only sees the debounced value.
  const debouncedCve = useDebouncedValue(filterCve, 300)
  const debouncedNameKw = useDebouncedValue(filterNameKw, 300)
  const debouncedHostKw = useDebouncedValue(filterHostKw, 300)
  const [batchModal, setBatchModal] = useState(false)
  const [detailId, setDetailId] = useState<string | null>(null)

  // Load business groups from the /host-stats endpoint so the operator
  // can pivot by business without leaving this page.
  useEffect(() => {
    getHostStats().then((r) => setHostStats(r.items || [])).catch(() => {})
  }, [])

  useEffect(() => {
    fetchData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterSev, filterStatus, debouncedCve, debouncedNameKw, debouncedHostKw, filterGroup, filterAiOnly, dateRange])

  const fetchData = async () => {
    setLoading(true)
    try {
      const r = await listVulns({
        severity: filterSev,
        status: filterStatus,
        cve_keyword: debouncedCve || undefined,
        name_keyword: debouncedNameKw || undefined,
        hostname_keyword: debouncedHostKw || undefined,
        group: filterGroup,
        ai_processed: filterAiOnly === "ai" ? true : filterAiOnly === "pending" ? false : undefined,
        date_from: dateRange?.[0],
        date_to: dateRange?.[1],
      })
      setFindings(r.items)
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
    {
      title: "AI 处理", dataIndex: "ai_processed", key: "ai_processed", width: 110,
      render: (v: boolean | undefined, record: VulnFinding) => (
        <AiEvidenceBadge
          aiProcessed={v}
          aiReason={record.ai_reason}
          size="compact"
        />
      ),
    },
    {
      title: "状态", dataIndex: "status", key: "status", width: 130,
      render: (v: string, record: VulnFinding) => (
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
    { title: "发现时间", dataIndex: "detected_at", key: "detected_at", width: 110, render: (v: string) => formatBeijing(v) },
    { title: "修复时间", dataIndex: "last_fixed_at", key: "last_fixed_at", width: 110,
      render: (v: string | null | undefined, record: VulnFinding) => v ? <Tooltip title={`首次: ${formatBeijing(record.first_fixed_at)}`}>{formatBeijing(v)}</Tooltip> : "-" },
    {
      title: "操作", key: "action", width: 70, fixed: "right" as const,
      render: (_: VulnFinding, record: VulnFinding) => (
        <Button size="small" type="link" icon={<EyeOutlined />} onClick={() => setDetailId(record.finding_id)}>详情</Button>
      ),
    },
  ]

  return (
    <Card
      title="漏洞清单"
      extra={
        <Space wrap>
          <Input
            placeholder="CVE (如 2024-1234)"
            allowClear
            style={{ width: 150 }}
            value={filterCve}
            onChange={(e) => setFilterCve(e.target.value)}
            prefix={<SearchOutlined />}
          />
          <Input
            placeholder="主机关键词"
            allowClear
            style={{ width: 140 }}
            value={filterHostKw}
            onChange={(e) => setFilterHostKw(e.target.value)}
          />
          <Input
            placeholder="漏洞名关键词"
            allowClear
            style={{ width: 140 }}
            value={filterNameKw}
            onChange={(e) => setFilterNameKw(e.target.value)}
          />
          <Select placeholder="业务归属" allowClear style={{ width: 140 }} value={filterGroup} onChange={setFilterGroup}
            options={hostStats.map((g) => ({ label: `${g.group} (${g.total})`, value: g.group }))} />
          <Select placeholder="严重等级" allowClear style={{ width: 110 }} value={filterSev} onChange={setFilterSev}
            options={Object.entries(SEV_LABEL).map(([k, v]) => ({ label: v, value: k }))} />
          <Select placeholder="状态" allowClear style={{ width: 110 }} value={filterStatus} onChange={setFilterStatus}
            options={STATUS_ACTIONS.map(a => ({ label: a.label, value: a.value }))} />
          <Select placeholder="AI 处理" style={{ width: 120 }} value={filterAiOnly} onChange={setFilterAiOnly}
            options={[
              { label: "全部", value: "all" },
              { label: "AI 已处理", value: "ai" },
              { label: "等待补扫", value: "pending" },
            ]} />
          <DatePicker.RangePicker
            showTime
            onChange={(vals) => {
              if (!vals || !vals[0] || !vals[1]) { setDateRange(null); return }
              setDateRange([vals[0].toISOString(), vals[1].toISOString()])
            }}
          />
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
        scroll={{ x: 1300 }}
        rowSelection={{
          selectedRowKeys: selectedKeys,
          onChange: (keys) => setSelectedKeys(keys as string[]),
        }}
        pagination={{ pageSize: 20 }}
        locale={{ emptyText: "暂无漏洞记录，请先执行扫描" }}
      />

      <Modal open={batchModal} title="批量更新状态" onCancel={() => setBatchModal(false)} footer={null}>
        <p>将 {selectedKeys.length} 条记录更新为：</p>
        <Space direction="vertical" style={{ width: "100%" }}>
          {STATUS_ACTIONS.map(a => (
            <Button key={a.value} block onClick={() => batchUpdateStatus(a.value)}>
              {a.icon} {a.label}
            </Button>
          ))}
        </Space>
      </Modal>

      <VulnDetailDrawer
        findingId={detailId}
        onClose={() => setDetailId(null)}
        onUpdated={() => fetchData()}
      />
    </Card>
  )

}
