import { useState, useEffect, useMemo, type Key } from "react"
import { Card, Tabs, Form, Input, Button, Select, message, Table, Tag, Popconfirm, Tooltip, Space } from "antd"
import { ThunderboltOutlined, MessageOutlined, DeleteOutlined, RobotOutlined } from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import api, { listHosts, getReport, type Host } from "../api/client"
import { deleteScanTask, batchDeleteScanTasks } from "../api/client"
import { formatBeijing } from "../utils/time"
import { showError } from "../utils/showError"
import TargetSelector from "../components/TargetSelector"
import ChatScan from "../components/ChatScan"

interface ScanTask { task_id: string; source: string; engine?: string; targets: string[]; target_groups?: string[]; status: string; created_at: string; stats: { total: number; done: number; failed: number } }

export default function ScanTaskPage() {
  const [submitting, setSubmitting] = useState(false)
  const [tasks, setTasks] = useState<ScanTask[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([])
  const [batchDeleting, setBatchDeleting] = useState(false)
  // 受控 tab：默认 tasks（用户从监控页返回时停留在任务列表，而非对话式）。
  const [activeTab, setActiveTab] = useState("tasks")
  // 2026-07-29 UX upgrade: cache host -> group lookup so the task table
  // can show a "业务归属" column without N+1 queries.
  const [hostGroupByName, setHostGroupByName] = useState<Record<string, string>>({})
  // AI 处理进度: task_id -> {total, processed, pending, model}
  const [aiProgress, setAiProgress] = useState<Record<string, { processed: number; pending: number; model?: string; aiProcessed?: boolean }>>({})
  // 分类搜索筛选 (2026-07-31 UX upgrade). engine + source 一起把任务表
  // 收敛到 "所有 nuclei 扫描" / "所有对话扫描" 这类常见检索。
  const [taskFilters, setTaskFilters] = useState<{ engine?: string; source?: string }>({})
  // V12 5.8: server-side pagination (the backend used to truncate at 50).
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [total, setTotal] = useState(0)
  const navigate = useNavigate()

  // mount 时默认在 tasks tab，自动加载任务列表；分页变化时重新加载。
  useEffect(() => { fetchTasks() }, [page, pageSize])
  // P1-UX (2026-07-22): dialog-created tasks set sessionStorage so we
  // refresh the list automatically when the operator returns to this tab.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === "secagent:task-created" && e.newValue) fetchTasks()
    }
    const last = (() => {
      try { return sessionStorage.getItem("secagent:task-created") } catch { return null }
    })()
    if (last) {
      // also fire on initial mount if a recent task-create event was set
      // in this tab within the last 30s
      const ts = Number(last)
      if (Number.isFinite(ts) && Date.now() - ts < 30000) fetchTasks()
    }
    window.addEventListener("storage", onStorage)
    return () => window.removeEventListener("storage", onStorage)
  }, [])

  // 2026-07-29 UX upgrade: load host->group mapping once and refresh
  // AI progress for the most recent N tasks so the columns don't stay
  // empty.
  useEffect(() => {
    let alive = true
    listHosts({}).then((r) => {
      if (!alive) return
      const m: Record<string, string> = {}
      ;(r.items || []).forEach((h: Host) => { if (h.hostname && h.group) m[h.hostname] = h.group })
      setHostGroupByName(m)
    }).catch(() => {})
    return () => { alive = false }
  }, [])

  const refreshAiProgress = async (taskList: ScanTask[]) => {
    // V9 3.3 (2026-07-30): previously a serial for-loop fired
    // 2N requests for the 20 most recent tasks. Now we run them in
    // parallel via Promise.all (so wall-clock = single round-trip)
    // and feed the responses back into the existing aiProgress map.
    // Per-task failures are swallowed (best-effort UX hint).
    // V12 5.8 (2026-08-02): the old slice(0, 20) meant page 2+ tasks
    // never got AI progress -- process the WHOLE current page instead.
    const recent = taskList.slice(0, 100)
    const settled = await Promise.all(
      recent.map(async (t) => {
        try {
          const [r, findingsResp] = await Promise.all([
            getReport(t.task_id),
            // V12 5.8 (2026-08-02): count AI status from the RESULTS index
            // (/tasks/{id}/findings) instead of /vulnscan/results -- the
            // latter queries vulns, so reconcile-merged tasks read as 0
            // findings and rendered a misleading "部分处理 0/0".
            api.get<{ items: Array<{ ai_processed?: boolean }> }>(
              `/vulnscan/tasks/${t.task_id}/findings`,
            ),
          ])
          const items = findingsResp.data?.items || []
          const processed = items.filter((v) => v.ai_processed === true).length
          return {
            taskId: t.task_id,
            progress: {
              processed,
              pending: items.length - processed,
              model: r?.ai_model,
              aiProcessed: r?.ai_processed,
            },
          }
        } catch {
          return null
        }
      }),
    )
    const updates: typeof aiProgress = {}
    for (const s of settled) {
      if (s) updates[s.taskId] = s.progress
    }
    setAiProgress((prev) => ({ ...prev, ...updates }))
  }

  const handleSubmit = async (source: string, extra?: any) => {
    setSubmitting(true)
    try {
      const body: any = { source }
      body.targets = extra?.targets || []
      // modules is optional; backend defaults to ["sys_vuln","baseline"]
      // for matcher and ignores modules for nuclei.
      body.modules = extra?.modules
      body.engine = extra?.engine || "matcher"
      // Parse comma-separated ports into an int[]. Empty / unset =
      // backend defaults to "scan every listening TCP port on host".
      if (typeof extra?.nuclei_ports === 'string') {
        body.nuclei_ports = extra.nuclei_ports
          .split(',')
          .map((s: string) => parseInt(s.trim(), 10))
          .filter((n: number) => Number.isFinite(n) && n > 0 && n < 65536)
      }
      const res = await api.post("/vulnscan/tasks", body)
      message.success("任务已创建")
      navigate(`/scan-monitor/${res.data.task_id}`)
    } catch (err) { showError(err, "创建失败") }
    finally { setSubmitting(false) }
  }

  const fetchTasks = async () => {
    setLoading(true)
    try {
      const res = await api.get("/vulnscan/tasks", {
        params: { page, page_size: pageSize },
      })
      const items: ScanTask[] = res.data.items
      setTasks(items)
      setTotal(res.data.total ?? items.length)
      // Fire and forget; updates state when each task resolves.
      void refreshAiProgress(items)
    } catch (err) { showError(err, "加载失败") }
    finally { setLoading(false) }
  }

  const handleDeleteTask = async (taskId: string) => {
    try {
      await deleteScanTask(taskId)
      message.success("任务记录已删除")
      fetchTasks()
    } catch (err) { showError(err, "删除失败") }
  }

  const handleBatchDelete = async () => {
    const ids = selectedRowKeys.map(String)
    setBatchDeleting(true)
    try {
      const res = await batchDeleteScanTasks(ids)
      const parts: string[] = [`已删除 ${res.deleted} 条`]
      if (res.not_found.length) parts.push(`${res.not_found.length} 条不存在`)
      if (res.failed.length) parts.push(`${res.failed.length} 条失败`)
      message.success(parts.join("，"))
      setSelectedRowKeys([])
      fetchTasks()
    } catch {
      message.error("批量删除失败")
    } finally {
      setBatchDeleting(false)
    }
  }

  // 2026-07-29 UX upgrade: prefer the target_groups field that the
  // server now persists on the ScanTask; fall back to the host
  // name -> group map for legacy tasks created before this field
  // existed (and for dialog-driven tasks where the group is unknown
  // at enqueue time).
  const renderEngine = (_: any, r: ScanTask) => {
    const e = r.engine || 'matcher'
    const map: Record<string, { color: string; label: string }> = {
      matcher: { color: 'blue', label: 'matcher' },
      nuclei: { color: 'purple', label: 'nuclei' },
      global: { color: 'magenta', label: '全局' },
    }
    const cfg = map[e] || { color: 'default', label: e }
    return <Tag color={cfg.color}>{cfg.label}</Tag>
  }

  const renderGroups = (_: any, r: ScanTask) => {
    const fromServer = Array.isArray(r.target_groups) ? r.target_groups : []
    const fromJoin = Array.from(new Set((r.targets || []).map((t) => hostGroupByName[t]).filter(Boolean)))
    const groups = Array.from(new Set([...fromServer, ...fromJoin]))
    if (!groups.length) return <span style={{ color: "#bbb" }}>-</span>
    const shown = groups.slice(0, 2)
    const rest = groups.length - shown.length
    return (
      <>
        {shown.map((g) => <Tag key={g} color="geekblue">{g}</Tag>)}
        {rest > 0 && <Tooltip title={groups.join(", ")}><Tag>+{rest}</Tag></Tooltip>}
      </>
    )
  }

  const renderAiProgress = (_: any, r: ScanTask) => {
    const p = aiProgress[r.task_id]
    if (!p) return <span style={{ color: "#bbb" }}>-</span>
    if (p.aiProcessed) {
      return <Tag icon={<RobotOutlined />} color="blue">AI 已处理{p.model ? " · " + p.model : ""}</Tag>
    }
    // V12 5.8 (2026-08-02): the old code rendered "部分处理 0/0" when the
    // vulns lookup came back empty (e.g. reconcile merged the records into
    // an older task). Distinguish "no vulns data" (-) from genuine partial
    // AI progress. "等待补扫 (N)" = N vulns never seen by the LLM.
    const total = p.processed + p.pending
    if (total === 0) return <span style={{ color: "#bbb" }}>-</span>
    if (p.processed === 0) {
      return <Tag color="default">等待补扫 ({p.pending})</Tag>
    }
    return <Tag color="orange">部分处理 {p.processed}/{total}</Tag>
  }

  // V12 阶段 3.2: columns 数组 memoize。deps 必须包含 render 闭包捕获的
  // state（aiProgress / hostGroupByName）-- 空 deps 会冻结首次渲染的闭包，
  // AI 处理列与业务归属列在数据异步更新后永远显示旧值。
  const columns = useMemo(() => [
    { title: "任务ID", dataIndex: "task_id", key: "task_id", ellipsis: true, width: 150 },
    { title: "来源", dataIndex: "source", key: "source", width: 70, render: (v: string) => v === "dialog" ? "对话" : "手动" },
    { title: "引擎", key: "engine", width: 90, render: renderEngine },
    { title: "业务归属", key: "groups", width: 200, render: renderGroups },
    { title: "目标数", key: "targets", width: 80, render: (_: any, r: ScanTask) => r.targets?.length || 0 },
    { title: "进度", key: "progress", width: 110, render: (_: any, r: ScanTask) => `${r.stats?.done || 0}/${r.stats?.total || 0}` },
    { title: "AI 处理", key: "ai", width: 180, render: renderAiProgress },
    { title: "状态", dataIndex: "status", key: "status", width: 100, render: (v: string) => {
      const colors: any = { queued: "default", dispatching: "processing", scanning: "processing", analyzing: "processing", completed: "success", failed: "error" }
      return <Tag color={colors[v] || "default"}>{v}</Tag>
    }},
    { title: "创建时间", dataIndex: "created_at", key: "created_at", width: 110, render: (v: string) => formatBeijing(v) },
    { title: "操作", key: "action", width: 140, render: (_: any, r: ScanTask) => (
      <>
        <Button size="small" type="link" onClick={() => navigate(`/scan-monitor/${r.task_id}`)}>监控</Button>
        <Popconfirm title="删除该任务记录?" description="将删除任务及关联结果/漏洞/报告" onConfirm={() => handleDeleteTask(r.task_id)}>
          <Button size="small" type="link" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      </>
    )},
  ], [aiProgress, hostGroupByName])

  return (
    <div>
      <Tabs activeKey={activeTab} onChange={(k) => {
        setActiveTab(k)
        if (k === "tasks") fetchTasks()
      }} items={[
        {
          key: "dialog", label: <span><MessageOutlined /> 对话式</span>, children: (
            <ChatScan />
          )
        },
        {
          key: "manual", label: <span><ThunderboltOutlined /> 手动</span>, children: (
            <Card>
              <Form
                onFinish={(v) => handleSubmit("manual", {
                  targets: v.targets || [],
                  // modules only applies to matcher; nuclei/global ignore it
                  modules: v.engine === "matcher" ? v.modules : undefined,
                  engine: v.engine,
                  nuclei_ports: v.nuclei_ports,
                })}
                initialValues={{
                  engine: "matcher",
                  modules: ["sys_vuln", "baseline"],
                  nuclei_ports: "",
                }}
              >
                <Form.Item name="targets" label="目标主机" rules={[{ required: true, message: "请选择目标主机或主机组" }]}>
                  <TargetSelector />
                </Form.Item>
                <Form.Item name="engine" label="扫描引擎" tooltip="matcher 内部规则匹配器；nuclei = projectdiscovery 模板库；全局扫描 = matcher + nuclei 一次提交">
                  <Select
                    options={[
                      { label: "matcher (内部规则)", value: "matcher" },
                      { label: "nuclei (模板库)", value: "nuclei" },
                      { label: "全局扫描 (matcher + nuclei)", value: "global" },
                    ]}
                  />
                </Form.Item>
                {/*
                  Engine-driven form. matcher: pick CVE modules. nuclei:
                  扫描模块固定为 端口扫描；global：matcher 模块 + 端口
                  (nuclei) 并存。shouldUpdate triggers re-render when the
                  engine select changes.
                */}
                <Form.Item
                  noStyle
                  shouldUpdate={(prev, cur) => prev.engine !== cur.engine}
                >
                  {({ getFieldValue }) => {
                    const engine = getFieldValue("engine") as string
                    if (engine === "nuclei") {
                      return (
                        <>
                          <Form.Item label="扫描模块">
                            <Tag color="blue">端口扫描</Tag>
                            <span style={{ marginLeft: 8, color: "#999", fontSize: 12 }}>
                              nuclei 任务固定使用端口扫描
                            </span>
                          </Form.Item>
                          <Form.Item
                            name="nuclei_ports"
                            label="端口"
                            tooltip="留空 = 扫描主机上所有监听 TCP 端口；多个端口用英文逗号分隔"
                          >
                            <Input placeholder="如: 80, 443, 8000-8100" allowClear />
                          </Form.Item>
                        </>
                      )
                    }
                    if (engine === "global") {
                      return (
                        <>
                          <Form.Item label="扫描模块">
                            <Space size={4} wrap>
                              <Tag color="blue">端口扫描 (nuclei)</Tag>
                              <Tag color="geekblue">系统漏洞 / 安全基线 (matcher)</Tag>
                            </Space>
                          </Form.Item>
                          <Form.Item
                            name="modules"
                            label="扫描模块 (matcher)"
                            tooltip="全局扫描会同时运行内部规则匹配器与 nuclei 引擎"
                          >
                            <Select
                              mode="multiple"
                              options={[
                                { label: "系统漏洞", value: "sys_vuln" },
                                { label: "安全基线", value: "baseline" },
                              ]}
                            />
                          </Form.Item>
                          <Form.Item
                            name="nuclei_ports"
                            label="端口 (nuclei)"
                            tooltip="留空 = 扫描主机上所有监听 TCP 端口；多个端口用英文逗号分隔"
                          >
                            <Input placeholder="如: 80, 443, 8000-8100" allowClear />
                          </Form.Item>
                        </>
                      )
                    }
                    // matcher: pick CVE modules
                    return (
                      <Form.Item name="modules" label="扫描模块">
                        <Select
                          mode="multiple"
                          options={[
                            { label: "系统漏洞", value: "sys_vuln" },
                            { label: "安全基线", value: "baseline" },
                          ]}
                        />
                      </Form.Item>
                    )
                  }}
                </Form.Item>
                <Form.Item>
                  <Button type="primary" htmlType="submit" loading={submitting}>开始扫描</Button>
                </Form.Item>
              </Form>
            </Card>
          )
        },
        {
          key: "tasks", label: "任务列表", children: (
            <>
              <div style={{ marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <Space>
                  <Button onClick={fetchTasks} loading={loading}>刷新</Button>
                  {/*
                    分类搜索 (2026-07-31): 引擎 + 来源 两个筛选一起把列表收
                    敛到 operator 关心的范围，避免满屏手动/对话/nuclei 全
                    混在一起。两者都是 client-side 过滤（task 列表已分页）。
                  */}
                  <Select
                    allowClear
                    placeholder="引擎"
                    style={{ width: 130 }}
                    value={taskFilters.engine}
                    onChange={(v) => setTaskFilters((f) => ({ ...f, engine: v }))}
                    options={[
                      { label: 'matcher', value: 'matcher' },
                      { label: 'nuclei', value: 'nuclei' },
                      { label: '全局扫描', value: 'global' },
                    ]}
                  />
                  <Select
                    allowClear
                    placeholder="来源"
                    style={{ width: 120 }}
                    value={taskFilters.source}
                    onChange={(v) => setTaskFilters((f) => ({ ...f, source: v }))}
                    options={[
                      { label: '手动', value: 'manual' },
                      { label: '对话', value: 'dialog' },
                    ]}
                  />
                  {(taskFilters.engine || taskFilters.source) && (
                    <Button
                      size="small"
                      type="link"
                      onClick={() => setTaskFilters({})}
                    >
                      清空筛选
                    </Button>
                  )}
                  {selectedRowKeys.length > 0 && (
                    <Popconfirm
                      title={`批量删除 ${selectedRowKeys.length} 个任务记录?`}
                      description="将删除任务及关联结果/漏洞/报告；运行中的任务建议先取消"
                      onConfirm={handleBatchDelete}
                      disabled={batchDeleting}
                    >
                      <Button danger icon={<DeleteOutlined />} loading={batchDeleting}>
                        批量删除 ({selectedRowKeys.length})
                      </Button>
                    </Popconfirm>
                  )}
                </Space>
                {selectedRowKeys.length > 0 && (
                  <Button type="link" onClick={() => setSelectedRowKeys([])}>清空选择</Button>
                )}
              </div>
              <Table
                dataSource={tasks.filter((t) =>
                  (!taskFilters.engine || (t.engine || 'matcher') === taskFilters.engine) &&
                  (!taskFilters.source || t.source === taskFilters.source)
                )}
                columns={columns}
                rowKey="task_id"
                loading={loading}
                pagination={{
                  current: page,
                  pageSize,
                  total,
                  showSizeChanger: true,
                  pageSizeOptions: ["20", "50", "100"],
                  onChange: (p, ps) => { setPage(p); setPageSize(ps) },
                }}
                rowSelection={{
                  selectedRowKeys,
                  onChange: setSelectedRowKeys,
                }}
                locale={{ emptyText: "暂无扫描任务" }}
              />
            </>
          )
        },
      ]} />
    </div>
  )
}
