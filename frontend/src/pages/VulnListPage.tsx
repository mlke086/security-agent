import { useEffect, useState, useMemo } from "react"
import {
  Alert, Button, Card, DatePicker, Input, message, Modal, Segmented, Select, Space, Table, Tag, Tooltip,
} from "antd"
import {
  ArrowLeftOutlined, CheckCircleOutlined, CloseCircleOutlined, EyeOutlined, ReloadOutlined, SearchOutlined,
} from "@ant-design/icons"
import api, {
  getHostStats, getHostVulnSummary, listVulns,
  type HostStatsRow, type HostVulnSummaryRow, type VulnFinding,
} from "../api/client"
import { formatBeijing } from "../utils/time"
import { showError } from "../utils/showError"
import { useDebouncedValue } from "../utils/useDebouncedValue"
import AiEvidenceBadge from "../components/AiEvidenceBadge"
import VulnDetailDrawer from "../components/VulnDetailDrawer"

const SEV_COLORS: Record<string, string> = { critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue" }
const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" }
// 主机清单"漏洞情况"只展示四个主等级（info 并入低危语义，不单列）
const SEV_KEYS = ["critical", "high", "medium", "low"] as const
const STATUS_ACTIONS = [
  { label: "待修复", value: "open", color: "red", icon: <CloseCircleOutlined /> },
  { label: "已修复", value: "fixed", color: "green", icon: <CheckCircleOutlined /> },
  { label: "已接受", value: "accepted", color: "blue", icon: <CheckCircleOutlined /> },
]

type ViewMode = "host" | "vuln"

export default function VulnListPage() {
  // -- 视图切换（需求③：主机清单默认顶层，漏洞明细为钻取） -----------------
  const [viewMode, setViewMode] = useState<ViewMode>("host")
  // 钻取目标主机：点主机清单"漏洞明细"后进入漏洞视图并固定 agent_id 过滤
  const [drillAgent, setDrillAgent] = useState<HostVulnSummaryRow | null>(null)

  // -- 共享筛选（主机视图 + 漏洞视图都生效） --------------------------------
  const [filterSev, setFilterSev] = useState<string | undefined>()
  const [filterStatus, setFilterStatus] = useState<string | undefined>()
  const [filterGroup, setFilterGroup] = useState<string | undefined>()
  const [filterHostKw, setFilterHostKw] = useState("")
  const debouncedHostKw = useDebouncedValue(filterHostKw, 300)

  // -- 漏洞视图独有筛选 ----------------------------------------------------
  const [filterCve, setFilterCve] = useState("")
  const [filterNameKw, setFilterNameKw] = useState("")
  const [filterAiOnly, setFilterAiOnly] = useState<"all" | "ai" | "pending">("all")
  const [dateRange, setDateRange] = useState<[string, string] | null>(null)
  const [hostStats, setHostStats] = useState<HostStatsRow[]>([])
  const debouncedCve = useDebouncedValue(filterCve, 300)
  const debouncedNameKw = useDebouncedValue(filterNameKw, 300)

  // -- 漏洞明细数据（现扁平视图 + 钻取共用，钻取时带 agent_id） --------------
  const [findings, setFindings] = useState<VulnFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [batchModal, setBatchModal] = useState(false)
  const [detailId, setDetailId] = useState<string | null>(null)

  // -- 主机清单数据 ---------------------------------------------------------
  const [hostRows, setHostRows] = useState<HostVulnSummaryRow[]>([])
  const [hostTotal, setHostTotal] = useState(0)
  const [hostPage, setHostPage] = useState(1)
  const [hostPageSize, setHostPageSize] = useState(20)
  const [hostLoading, setHostLoading] = useState(false)

  // Load business groups from the /host-stats endpoint so the operator
  // can pivot by business without leaving this page.
  useEffect(() => {
    getHostStats().then((r) => setHostStats(r.items || [])).catch(() => {})
  }, [])

  // 主机清单：后端分页 + 30s 缓存，筛选变化时回到第一页
  const fetchHostSummary = async () => {
    setHostLoading(true)
    try {
      const r = await getHostVulnSummary({
        group: filterGroup,
        hostname_keyword: debouncedHostKw || undefined,
        severity: filterSev,
        status: filterStatus,
        page: hostPage,
        page_size: hostPageSize,
      })
      setHostRows(r.items)
      setHostTotal(r.total)
    } catch (err) {
      showError(err, "加载失败")
    } finally {
      setHostLoading(false)
    }
  }

  useEffect(() => {
    if (viewMode === "host") fetchHostSummary()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewMode, filterSev, filterStatus, filterGroup, debouncedHostKw, hostPage, hostPageSize])

  const drillInto = (row: HostVulnSummaryRow) => {
    setDrillAgent(row)
    setViewMode("vuln")
  }

  const backToHosts = () => {
    setViewMode("host")
    setDrillAgent(null)
  }

  // 漏洞明细：drill 状态下只查该主机（agent_id 精确过滤，hostname 可能重名）
  useEffect(() => {
    if (viewMode === "vuln") fetchData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewMode, filterSev, filterStatus, debouncedCve, debouncedNameKw, debouncedHostKw, filterGroup, filterAiOnly, dateRange, drillAgent])

  const fetchData = async () => {
    setLoading(true)
    try {
      const r = await listVulns({
        agent_id: drillAgent?.agent_id,
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
    } catch (err) {
      showError(err, "加载失败")
    } finally {
      setLoading(false)
    }
  }

  const updateStatus = async (id: string, newStatus: string) => {
    try {
      await api.patch("/vulnscan/vulns/" + id, { status: newStatus })
      message.success("状态已更新")
      fetchData()
    } catch (err) {
      showError(err, "更新失败")
    }
  }

  const batchUpdateStatus = async (newStatus: string) => {
    setBatchModal(false)
    for (const id of selectedKeys) {
      try {
        await api.patch("/vulnscan/vulns/" + id, { status: newStatus })
      } catch {
        /* continue */
      }
    }
    message.success("批量更新完成")
    setSelectedKeys([])
    fetchData()
  }

  // V12 阶段 3.2: memoize columns
  const columns = useMemo(() => [
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
      title: "操作", key: "action", width: 100, fixed: "right" as const,
      render: (_: VulnFinding, record: VulnFinding) => (
        <Button size="small" type="link" icon={<EyeOutlined />} style={{ padding: 0 }} onClick={() => setDetailId(record.finding_id)}>详情</Button>
      ),
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [])

  // 主机清单列（需求③）：漏洞情况按原始 severity 计数，0 也显示（置灰）
  const hostColumns = useMemo(() => [
    { title: "主机名", dataIndex: "hostname", key: "hostname", width: 140, render: (v: string, row: HostVulnSummaryRow) => v || <span style={{ color: "#999" }}>{row.agent_id.slice(0, 12)}…</span> },
    { title: "IP", dataIndex: "ip", key: "ip", width: 130, render: (v: string) => v || "-" },
    { title: "系统版本", dataIndex: "os", key: "os", ellipsis: true, render: (v: string) => v || "-" },
    {
      title: "漏洞情况", key: "severity_counts", width: 300,
      render: (_: unknown, row: HostVulnSummaryRow) => (
        <Space size={4} wrap>
          {SEV_KEYS.map(k => (
            <Tag
              key={k}
              color={SEV_COLORS[k]}
              style={!row.severity_counts[k] ? { opacity: 0.45 } : undefined}
            >
              {row.severity_counts[k] ?? 0} {SEV_LABEL[k]}
            </Tag>
          ))}
          <Tooltip title={`共 ${row.total} 条，待修复 ${row.open_count} / 已修复 ${row.fixed_count}`}>
            <Tag style={{ opacity: 0.75 }}>{row.total} 条</Tag>
          </Tooltip>
        </Space>
      ),
    },
    {
      title: "最近扫描时间", dataIndex: "last_scan_at", key: "last_scan_at", width: 150,
      render: (v: string) => (v ? formatBeijing(v) : "-"),
    },
    {
      title: "操作", key: "action", width: 110, fixed: "right" as const,
      render: (_: unknown, row: HostVulnSummaryRow) => (
        <Button size="small" type="link" icon={<EyeOutlined />} style={{ padding: 0 }} onClick={() => drillInto(row)}>
          漏洞明细
        </Button>
      ),
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [])

  const viewSwitch = (
    <Segmented
      value={viewMode}
      onChange={(v) => {
        const mode = v as ViewMode
        setViewMode(mode)
        if (mode === "host") setDrillAgent(null)
      }}
      options={[
        { label: "按主机查看", value: "host" },
        { label: "按漏洞查看", value: "vuln" },
      ]}
    />
  )

  return (
    <Card title={<Space>{viewSwitch}<span style={{ fontWeight: 600 }}>漏洞清单</span></Space>}
      extra={
        <Space wrap>
          {viewMode === "host" ? (
            <>
              <Input
                placeholder="主机关键词"
                allowClear
                style={{ width: 150 }}
                value={filterHostKw}
                onChange={(e) => { setFilterHostKw(e.target.value); setHostPage(1) }}
                prefix={<SearchOutlined />}
              />
              <Select placeholder="业务归属" allowClear style={{ width: 140 }} value={filterGroup}
                onChange={(v) => { setFilterGroup(v); setHostPage(1) }}
                options={hostStats.map((g) => ({ label: `${g.group} (${g.total})`, value: g.group }))} />
              <Select placeholder="严重等级" allowClear style={{ width: 110 }} value={filterSev}
                onChange={(v) => { setFilterSev(v); setHostPage(1) }}
                options={Object.entries(SEV_LABEL).map(([k, v]) => ({ label: v, value: k }))} />
              <Select placeholder="状态" allowClear style={{ width: 110 }} value={filterStatus}
                onChange={(v) => { setFilterStatus(v); setHostPage(1) }}
                options={STATUS_ACTIONS.map(a => ({ label: a.label, value: a.value }))} />
              <Button icon={<ReloadOutlined />} onClick={fetchHostSummary} loading={hostLoading}>刷新</Button>
            </>
          ) : (
            <>
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
            </>
          )}
        </Space>
      }
    >
      {viewMode === "host" ? (
        <Table
          dataSource={hostRows}
          columns={hostColumns}
          rowKey="agent_id"
          loading={hostLoading}
          scroll={{ x: 1000 }}
          pagination={{
            current: hostPage,
            pageSize: hostPageSize,
            total: hostTotal,
            showSizeChanger: true,
            pageSizeOptions: ["10", "20", "50"],
            showTotal: (t) => `共 ${t} 台主机`,
            onChange: (p, ps) => {
              setHostPage(p)
              if (ps !== hostPageSize) { setHostPageSize(ps); setHostPage(1) }
            },
          }}
          locale={{ emptyText: "暂无漏洞记录，请先执行扫描" }}
        />
      ) : (
        <>
          {drillAgent && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message={`正在查看主机 ${drillAgent.hostname || drillAgent.agent_id}${drillAgent.ip ? ` (${drillAgent.ip})` : ""} 的漏洞明细（${drillAgent.total} 条）`}
              action={<Button size="small" icon={<ArrowLeftOutlined />} onClick={backToHosts}>返回主机清单</Button>}
            />
          )}
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
            pagination={{ defaultPageSize: 20, showSizeChanger: true, pageSizeOptions: ["20", "50", "100"], showTotal: (t) => `共 ${t} 条` }}
            locale={{ emptyText: "暂无漏洞记录，请先执行扫描" }}
          />
        </>
      )}

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
