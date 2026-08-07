import { useCallback, useEffect, useRef, useState } from "react"
import {
  Alert, Button, Card, Checkbox, Drawer, Form, Input, message, Modal, Popconfirm, Select, Space, Table, Tag, Tooltip, Typography,
} from "antd"
import {
  DeleteOutlined, EyeOutlined, FileTextOutlined, PlusOutlined, ReloadOutlined, StopOutlined,
} from "@ant-design/icons"
import {
  assetScanStreamUrl, cancelAssetScanTask, createAssetScanTask, deleteAssetScanTask,
  getAssetScanAssets, getAssetScanReport, getAssetScanTask, getAssetScanVulns, listAssetScanTasks,
  type AssetScanAsset, type AssetScanReport, type AssetScanTask, type AssetScanVuln,
} from "../api/client"
import { formatBeijing } from "../utils/time"
import { showError } from "../utils/showError"

const SEV_COLORS: Record<string, string> = { critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue", unknown: "default" }
const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示", unknown: "未知" }
const STATUS_COLORS: Record<string, string> = {
  queued: "blue", running: "purple", completed: "green",
  failed: "red", cancelled: "default", cancelling: "orange",
}
const STATUS_LABEL: Record<string, string> = {
  queued: "排队中", running: "扫描中", completed: "已完成",
  failed: "失败", cancelled: "已取消", cancelling: "取消中",
}
const STEPS = ["parse", "discover", "fingerprint", "match", "llm", "report"]

export default function AssetScanPage() {
  // -- 任务列表 --------------------------------------------------------------
  const [tasks, setTasks] = useState<AssetScanTask[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [loading, setLoading] = useState(false)

  // -- 创建表单 --------------------------------------------------------------
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form] = Form.useForm()

  // -- 任务详情 --------------------------------------------------------------
  const [selected, setSelected] = useState<AssetScanTask | null>(null)
  const [assets, setAssets] = useState<AssetScanAsset[]>([])
  const [vulns, setVulns] = useState<AssetScanVuln[]>([])
  const [report, setReport] = useState<AssetScanReport | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
  const [sseStep, setSseStep] = useState<string | null>(null)
  const sseRef = useRef<EventSource | null>(null)
  const aliveRef = useRef(true)

  const fetchTasks = useCallback(async (p = page, ps = pageSize) => {
    setLoading(true)
    try {
      const r = await listAssetScanTasks({ page: p, page_size: ps })
      setTasks(r.items)
      setTotal(r.total)
    } catch (err) {
      showError(err, "加载任务失败")
    } finally {
      setLoading(false)
    }
  }, [page, pageSize])

  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
      if (sseRef.current) { sseRef.current.close(); sseRef.current = null }
    }
  }, [])

  useEffect(() => {
    fetchTasks()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, pageSize])

  // -- 创建任务 --------------------------------------------------------------
  const handleCreate = async () => {
    try {
      const values = await form.validateFields()
      setCreating(true)
      const targets = values.targets.split("\n").map((t: string) => t.trim()).filter(Boolean)
      const ports = values.ports
        ? values.ports.split(",").map((p: string) => parseInt(p.trim(), 10)).filter((p: number) => !Number.isNaN(p))
        : []
      const r = await createAssetScanTask({
        targets,
        ports,
        engine: values.engine,
        modules: values.modules,
        schedule: values.schedule || "",
      })
      message.success(`任务已入队: ${r.task_id.slice(0, 8)}…`)
      setCreateOpen(false)
      form.resetFields()
      fetchTasks(1)
    } catch (err) {
      // antd 表单校验错误（{ errorFields: [...] }）不提示
      if (err && typeof err === "object" && "errorFields" in err) return
      showError(err, "创建任务失败")
    } finally {
      setCreating(false)
    }
  }

  // -- 任务详情 + SSE --------------------------------------------------------
  const openDetail = async (task: AssetScanTask) => {
    setSelected(task)
    setAssets([])
    setVulns([])
    setReport(null)
    setSseStep(null)
    setDetailLoading(true)
    // SSE 进度流（running/queued 时订阅）
    if (sseRef.current) { sseRef.current.close(); sseRef.current = null }
    if (task.status === "running" || task.status === "queued") {
      const source = new EventSource(assetScanStreamUrl(task.task_id))
      sseRef.current = source
      source.onmessage = (e) => {
        if (!e.data || e.data === ": heartbeat") return
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === "step" && msg.step) setSseStep(msg.step)
        } catch { /* ignore */ }
      }
      source.onerror = () => {
        if (source.readyState === EventSource.CLOSED && sseRef.current === source) {
          source.close()
          sseRef.current = null
        }
      }
    }
    try {
      const [a, v] = await Promise.all([
        getAssetScanAssets(task.task_id),
        getAssetScanVulns(task.task_id),
      ])
      if (aliveRef.current) {
        setAssets(a.items)
        setVulns(v.items)
      }
    } catch (err) {
      if (aliveRef.current) showError(err, "加载扫描结果失败")
    } finally {
      if (aliveRef.current) setDetailLoading(false)
    }
  }

  const closeDetail = () => {
    if (sseRef.current) { sseRef.current.close(); sseRef.current = null }
    setSelected(null)
  }

  // 详情打开期间每 10s 轮询任务状态（SSE 之外的状态兜底）
  useEffect(() => {
    if (!selected) return
    const t = setInterval(() => {
      getAssetScanTask(selected.task_id).then((task) => {
        if (aliveRef.current) setSelected(task)
      }).catch(() => {})
    }, 10000)
    return () => clearInterval(t)
  }, [selected?.task_id]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleCancel = async (task: AssetScanTask) => {
    try {
      await cancelAssetScanTask(task.task_id)
      message.info("已发送取消请求")
      fetchTasks()
    } catch (err) {
      showError(err, "取消失败")
    }
  }

  const handleDelete = async (task: AssetScanTask) => {
    try {
      await deleteAssetScanTask(task.task_id)
      message.success("任务已删除")
      if (selected?.task_id === task.task_id) closeDetail()
      fetchTasks()
    } catch (err) {
      showError(err, "删除失败")
    }
  }

  const loadReport = async () => {
    if (!selected) return
    try {
      const r = await getAssetScanReport(selected.task_id)
      setReport(r)
      setReportOpen(true)
    } catch (err) {
      showError(err, "报告尚未生成")
    }
  }

  // -- 渲染 ----------------------------------------------------------------
  const stepIndex = sseStep ? STEPS.indexOf(sseStep) : -1

  const columns = [
    { title: "任务 ID", dataIndex: "task_id", key: "task_id", width: 90, render: (v: string) => <Typography.Text code>{v.slice(0, 8)}…</Typography.Text> },
    { title: "目标", dataIndex: "targets", key: "targets", ellipsis: true, render: (v: string[]) => v?.join(", ") || "-" },
    { title: "引擎", dataIndex: "engine", key: "engine", width: 80, render: (v: string) => <Tag>{v}</Tag> },
    {
      title: "状态", dataIndex: "status", key: "status", width: 100,
      render: (v: string) => <Tag color={STATUS_COLORS[v] || "default"}>{STATUS_LABEL[v] || v}</Tag>,
    },
    { title: "创建时间", dataIndex: "created_at", key: "created_at", width: 150, render: (v: string) => formatBeijing(v) },
    {
      title: "操作", key: "action", width: 200, fixed: "right" as const,
      render: (_: unknown, task: AssetScanTask) => (
        <Space size={4}>
          <Button size="small" type="link" icon={<EyeOutlined />} style={{ padding: 0 }} onClick={() => openDetail(task)}>详情</Button>
          {(task.status === "running" || task.status === "queued") && (
            <Button size="small" type="link" danger icon={<StopOutlined />} style={{ padding: 0 }} onClick={() => handleCancel(task)}>取消</Button>
          )}
          <Popconfirm title="删除任务及全部扫描结果？" onConfirm={() => handleDelete(task)}>
            <Button size="small" type="link" danger icon={<DeleteOutlined />} style={{ padding: 0 }}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const assetColumns = [
    { title: "IP", dataIndex: "ip", key: "ip", width: 130 },
    { title: "主机名", dataIndex: "hostname", key: "hostname", width: 140, render: (v: string) => v || "-" },
    { title: "系统", dataIndex: "os_guess", key: "os_guess", width: 130, render: (v: string) => v || "-" },
    {
      title: "开放端口", dataIndex: "ports", key: "ports",
      render: (v: number[]) => v?.length ? v.join(", ") : "-",
    },
    {
      title: "服务", dataIndex: "services", key: "services",
      render: (v: AssetScanAsset["services"]) => v?.length
        ? v.slice(0, 6).map((s) => (
            <Tag key={`${s.port}:${s.name}`} style={{ marginBottom: 2 }}>
              {s.port}/{s.name}{s.version ? ` ${s.version}` : ""}
            </Tag>
          ))
        : "-",
    },
  ]

  const vulnColumns = [
    { title: "IP", dataIndex: "ip", key: "ip", width: 130 },
    { title: "端口", dataIndex: "port", key: "port", width: 70, render: (v: number) => v || "-" },
    { title: "CVE", dataIndex: "cve", key: "cve", width: 130, render: (v: string | null) => v || "-" },
    { title: "模板", dataIndex: "template_id", key: "template_id", width: 130, render: (v: string | null) => v || "-" },
    { title: "名称", dataIndex: "name", key: "name", ellipsis: true },
    {
      title: "严重等级", dataIndex: "severity", key: "severity", width: 90,
      render: (v: string, row: AssetScanVuln) => (
        <Space size={4}>
          <Tag color={SEV_COLORS[row.ai_severity || v] || "default"}>{SEV_LABEL[row.ai_severity || v] || row.ai_severity || v}</Tag>
          {row.ai_processed ? <Tooltip title={row.ai_reason || "AI 已研判"}><Tag color="cyan">AI</Tag></Tooltip> : null}
        </Space>
      ),
    },
    { title: "状态", dataIndex: "status", key: "status", width: 80, render: (v: string) => <Tag>{v}</Tag> },
  ]

  return (
    <Card
      title="内网资产扫描"
      extra={
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建扫描任务</Button>
          <Button icon={<ReloadOutlined />} onClick={() => fetchTasks()} loading={loading}>刷新</Button>
        </Space>
      }
    >
      {/* 创建任务 */}
      <Modal
        title="创建资产扫描任务"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={handleCreate}
        confirmLoading={creating}
        okText="入队扫描"
        width={640}
      >
        <Alert
          type="warning" showIcon style={{ marginBottom: 12 }}
          message="扫描目标仅限授权资产；单网段不超过 /22，单任务最多 500 个目标。"
        />
        <Form form={form} layout="vertical" initialValues={{ engine: "fast", modules: ["discovery", "fingerprint", "cve", "nuclei"] }}>
          <Form.Item
            name="targets" label="目标（每行一个 IP 或 CIDR）" required
            rules={[{ required: true, message: "请输入扫描目标" }]}
          >
            <Input.TextArea rows={4} placeholder={"10.0.0.0/24\n10.0.1.5"} />
          </Form.Item>
          <Space size={16} style={{ width: "100%" }} align="start">
            <Form.Item name="ports" label="端口（可选，逗号分隔，如 80,443,22）">
              <Input placeholder="留空 = 引擎默认" style={{ width: 220 }} />
            </Form.Item>
            <Form.Item name="engine" label="扫描引擎">
              <Select style={{ width: 160 }} options={[
                { label: "fast（常用端口）", value: "fast" },
                { label: "full（全端口）", value: "full" },
                { label: "global（masscan+nmap）", value: "global" },
              ]} />
            </Form.Item>
          </Space>
          <Form.Item name="modules" label="扫描模块">
            <Checkbox.Group options={[
              { label: "存活发现", value: "discovery" },
              { label: "服务指纹", value: "fingerprint" },
              { label: "CVE 匹配", value: "cve" },
              { label: "Nuclei 模板", value: "nuclei" },
              { label: "弱口令（默认关闭）", value: "brute" },
            ]} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 任务列表 */}
      <Table
        dataSource={tasks}
        columns={columns}
        rowKey="task_id"
        loading={loading}
        scroll={{ x: 900 }}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 个任务`,
          onChange: (p, ps) => { setPage(p); if (ps !== pageSize) { setPageSize(ps); setPage(1) } },
        }}
        locale={{ emptyText: "暂无扫描任务" }}
      />

      {/* 任务详情 */}
      <Drawer
        title={selected ? `任务 ${selected.task_id.slice(0, 8)}… - ${STATUS_LABEL[selected.status] || selected.status}` : "任务详情"}
        open={!!selected}
        onClose={closeDetail}
        width={920}
        extra={
          <Space>
            <Button size="small" icon={<FileTextOutlined />} onClick={loadReport}>查看报告</Button>
            <Button size="small" icon={<ReloadOutlined />} onClick={() => selected && openDetail(selected)}>刷新结果</Button>
          </Space>
        }
      >
        {selected && (
          <>
            {selected.error && <Alert type="error" showIcon style={{ marginBottom: 12 }} message={`失败原因: ${selected.error}`} />}
            {(selected.status === "running" || selected.status === "queued") && (
              <Alert
                type="info" showIcon style={{ marginBottom: 12 }}
                message={sseStep ? `正在执行: ${sseStep} 阶段` : "任务排队中或正在启动…"}
                action={sseStep ? <Tag color="purple">步骤 {stepIndex + 1}/{STEPS.length}</Tag> : undefined}
              />
            )}
            <Typography.Paragraph style={{ marginBottom: 8 }}>
              <Typography.Text type="secondary">
                目标: {selected.targets.join(", ")} ｜ 引擎: {selected.engine} ｜ 模块: {selected.modules.join("/")}
                {selected.finished_at ? ` ｜ 完成于 ${formatBeijing(selected.finished_at)}` : ""}
              </Typography.Text>
            </Typography.Paragraph>

            <Card size="small" title={`资产 (${assets.length})`} style={{ marginBottom: 16 }}>
              <Table
                dataSource={assets}
                columns={assetColumns}
                rowKey="ip"
                size="small"
                loading={detailLoading}
                pagination={false}
                locale={{ emptyText: "暂无资产数据" }}
              />
            </Card>

            <Card size="small" title={`漏洞 (${vulns.length})`} style={{ marginBottom: 16 }}>
              <Table
                dataSource={vulns}
                columns={vulnColumns}
                rowKey="vuln_id"
                size="small"
                loading={detailLoading}
                pagination={{ defaultPageSize: 10, showSizeChanger: true, pageSizeOptions: ["10", "20", "50"] }}
                expandable={{
                  expandedRowRender: (row: AssetScanVuln) => (
                    <div style={{ maxWidth: 800 }}>
                      {row.evidence ? <p><b>证据:</b> {row.evidence}</p> : null}
                      {row.ai_reason ? <p><b>AI 研判:</b> {row.ai_reason}</p> : null}
                      {row.fix_advice ? <p><b>修复建议:</b> {row.fix_advice}</p> : null}
                    </div>
                  ),
                }}
                locale={{ emptyText: "暂无漏洞，或匹配/扫描尚未完成" }}
              />
            </Card>
          </>
        )}
      </Drawer>

      {/* 报告 */}
      <Modal
        title={`扫描报告 - ${report?.task_id?.slice(0, 8) || ""}…`}
        open={reportOpen}
        onCancel={() => setReportOpen(false)}
        footer={<Button type="primary" onClick={() => setReportOpen(false)}>关闭</Button>}
        width={720}
      >
        {report && (
          <>
            <Typography.Paragraph><b>{report.summary}</b></Typography.Paragraph>
            <Typography.Paragraph>
              <Space wrap>
                <Tag>存活 {report.stats.hosts_alive}</Tag>
                <Tag>开放端口 {report.stats.open_ports}</Tag>
                <Tag>服务 {report.stats.services}</Tag>
                <Tag>漏洞 {report.stats.vulns}</Tag>
                {Object.entries(report.stats.by_severity || {}).map(([sev, n]) => (
                  <Tag key={sev} color={SEV_COLORS[sev] || "default"}>{SEV_LABEL[sev] || sev}: {n}</Tag>
                ))}
              </Space>
            </Typography.Paragraph>
            {report.ai_analysis && <Typography.Paragraph><b>AI 分析:</b> {report.ai_analysis}</Typography.Paragraph>}
            <Typography.Paragraph>
              <b>Top 漏洞:</b>
              <ul style={{ marginTop: 4 }}>
                {(report.top_vulns || []).slice(0, 10).map((v, i) => (
                  <li key={i}>
                    <Tag color={SEV_COLORS[v.severity] || "default"}>{SEV_LABEL[v.severity] || v.severity}</Tag>
                    {v.ip}:{v.port} {v.cve || v.name}
                  </li>
                ))}
              </ul>
            </Typography.Paragraph>
            <Typography.Paragraph>
              <b>建议:</b>
              <ul style={{ marginTop: 4 }}>{(report.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}</ul>
            </Typography.Paragraph>
          </>
        )}
      </Modal>
    </Card>
  )
}
