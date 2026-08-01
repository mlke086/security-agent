import { useEffect, useState, useCallback, useMemo } from "react"
import { Card, Button, Descriptions, Tag, message, Space, Spin, Table, Input, Select, Tabs, Tooltip, Upload, Modal, Typography } from "antd"
import { SafetyCertificateOutlined, ReloadOutlined, SearchOutlined, UploadOutlined, QuestionCircleOutlined, CloudSyncOutlined, GlobalOutlined, ApiOutlined, ExperimentOutlined, EyeOutlined } from "@ant-design/icons"
import { listRules, getRuleVersion, syncRules, importRules, syncRulesToAgents, syncNucleiTemplates, listNucleiTemplates, syncNucleiTemplatesLibrary, importNucleiTemplatesZip, type RuleItem, type NucleiTemplateMeta, getSigmaRules, getSigmaSummary, type SigmaRuleItem, type SigmaSummary } from "../api/client"
import NucleiTemplateViewer from "../components/NucleiTemplateViewer"

const { Text, Paragraph } = Typography

const SEVERITY_CONFIG: Record<string, { color: string; label: string }> = {
  critical: { color: "red", label: "严重" },
  high: { color: "volcano", label: "高危" },
  medium: { color: "gold", label: "中危" },
  low: { color: "green", label: "低危" },
  info: { color: "blue", label: "提示" },
}

const CATEGORY_CONFIG: Record<string, { color: string; label: string }> = {
  sys_vuln: { color: "red", label: "漏洞扫描规则" },
  baseline: { color: "blue", label: "安全基线规则" },
}

const CHECK_TYPE_LABEL: Record<string, string> = {
  package_version: "软件包版本",
  kernel_version: "内核版本",
  config_check: "配置检查",
}

export default function RulesPage() {
  // F5 (2026-07-21): one `syncing` flag for both online sources used
  // to make the other button spin while one was in flight. Each source
  // gets its own flag now.
  const [syncingNvd, setSyncingNvd] = useState(false)
  const [syncingGithub, setSyncingGithub] = useState(false)
  const [syncingToAgents, setSyncingToAgents] = useState(false)
  const [syncingNucleiTpl, setSyncingNucleiTpl] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importHelpOpen, setImportHelpOpen] = useState(false)
  const [version, setVersion] = useState("")
  const [lastCount, setLastCount] = useState<number | null>(null)
  const [loadingVer, setLoadingVer] = useState(false)

  const [rules, setRules] = useState<RuleItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [category, setCategory] = useState<string>("")
  const [severity, setSeverity] = useState<string | undefined>(undefined)
  const [q, setQ] = useState("")
  // P2-11 修复：搜索框逐键触发请求改为 debounce 300ms，避免每个字符都打一次接口。
  const [debouncedQ, setDebouncedQ] = useState("")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [activeTab, setActiveTab] = useState("all")

  // Phase 6: Sigma detection rules state
  const [sigmaSummary, setSigmaSummary] = useState<SigmaSummary | null>(null)
  const [sigmaRules, setSigmaRules] = useState<SigmaRuleItem[]>([])
  const [sigmaLoading, setSigmaLoading] = useState(false)
  const [sigmaCategory, setSigmaCategory] = useState<string | undefined>(undefined)
  const [sigmaOs, setSigmaOs] = useState<string | undefined>(undefined)
  const [sigmaLevel, setSigmaLevel] = useState<string | undefined>(undefined)
  const [sigmaDetectorOnly, setSigmaDetectorOnly] = useState<boolean | null>(null)

  // Nuclei 模板库（内容存 Nacos，元数据走 ES manifest）
  const [nucleiTpls, setNucleiTpls] = useState<NucleiTemplateMeta[]>([])
  const [nucleiTotal, setNucleiTotal] = useState(0)
  const [nucleiLoading, setNucleiLoading] = useState(false)
  const [nucleiCategory, setNucleiCategory] = useState<string | undefined>(undefined)
  const [nucleiQ, setNucleiQ] = useState("")
  const [nucleiDebouncedQ, setNucleiDebouncedQ] = useState("")
  const [nucleiPage, setNucleiPage] = useState(1)
  const [nucleiPageSize, setNucleiPageSize] = useState(20)
  const [nucleiVer, setNucleiVer] = useState("")
  const [syncTplLoading, setSyncTplLoading] = useState(false)
  const [importTplLoading, setImportTplLoading] = useState(false)
  const [viewerPath, setViewerPath] = useState<string | null>(null)

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedQ(q)
      setPage(1)
    }, 300)
    return () => clearTimeout(t)
  }, [q])

  // Nuclei 模板搜索 debounce
  useEffect(() => {
    const t = setTimeout(() => {
      setNucleiDebouncedQ(nucleiQ)
      setNucleiPage(1)
    }, 300)
    return () => clearTimeout(t)
  }, [nucleiQ])

  const fetchNucleiTpls = useCallback(async () => {
    setNucleiLoading(true)
    try {
      const res = await listNucleiTemplates({
        category: nucleiCategory,
        q: nucleiDebouncedQ || undefined,
        page: nucleiPage,
        page_size: nucleiPageSize,
      })
      setNucleiTpls(res.items || [])
      setNucleiTotal(res.total || 0)
      setNucleiVer(res.version || "")
    } catch {
      message.error("加载模板库失败")
    } finally {
      setNucleiLoading(false)
    }
  }, [nucleiCategory, nucleiDebouncedQ, nucleiPage, nucleiPageSize])

  useEffect(() => {
    if (activeTab === "nuclei_templates") fetchNucleiTpls()
  }, [activeTab, fetchNucleiTpls])

  const fetchVersion = async () => {
    setLoadingVer(true)
    try {
      const res = await getRuleVersion()
      setVersion(res.version)
    } catch { /* ignore */ }
    finally { setLoadingVer(false) }
  }

  const fetchSigma = useCallback(async () => {
    setSigmaLoading(true)
    try {
      const [summary, list] = await Promise.all([
        getSigmaSummary().catch(() => null),
        getSigmaRules({
          category: sigmaCategory,
          os: sigmaOs,
          level: sigmaLevel,
          detector_supported: sigmaDetectorOnly ?? undefined,
        }).catch((e) => {
          // 404 = no manifest yet (operator has not run the importer)
          if (e?.response?.status === 404) {
            message.info("尚未导入 Sigma 规则,请在服务器上执行 scripts/import_sigma_rules.py")
          }
          return { total: 0, items: [] }
        }),
      ])
      setSigmaSummary(summary)
      setSigmaRules(list.items)
    } finally {
      setSigmaLoading(false)
    }
  }, [sigmaCategory, sigmaOs, sigmaLevel, sigmaDetectorOnly])

  useEffect(() => {
    if (activeTab === "detection") fetchSigma()
  }, [activeTab, fetchSigma])

  const fetchRules = useCallback(async () => {
    setLoading(true)
    try {
      const res = await listRules({
        category: category || undefined,
        severity,
        q: debouncedQ || undefined,
        page,
        page_size: pageSize,
      })
      setRules(res.items || [])
      setTotal(res.total || 0)
      setVersion(res.version)
    } catch {
      message.error("加载规则列表失败")
    } finally {
      setLoading(false)
    }
  }, [category, severity, debouncedQ, page, pageSize])

  useEffect(() => { fetchVersion() }, [])
  useEffect(() => { fetchRules() }, [fetchRules])

  const handleSync = async (source: "nvd" | "github") => {
    // F5 (2026-07-21): one busy flag per source so the OTHER button stops
    // spinning while this one runs.
    const setBusy = source === "nvd" ? setSyncingNvd : setSyncingGithub
    setBusy(true)
    try {
      const res = await syncRules(source)
      setVersion(res.version)
      setLastCount(res.count)
      const srcLabel = source === "nvd" ? "NVD(国外)" : "GitHub Advisory(国内)"
      message.success(`规则库已同步[${srcLabel}]：${res.count} 条规则 (v${res.version})`)
      fetchRules()
    } catch {
      message.error(source === "nvd"
        ? "NVD 同步失败 - 国内访问常超时，请在服务端配代理(NVD_PROXY)或用 GitHub/离线导入"
        : "GitHub Advisory 同步失败 - 请检查网络或增大 advisory_lookback_days")
    } finally {
      setBusy(false)
    }
  }

  const handleSyncToAgents = async () => {
    setSyncingToAgents(true)
    try {
      const res = await syncRulesToAgents()
      if (res.total === 0) {
        message.warning("当前无在线 agent")
      } else {
        message.success(`已向 ${res.synced}/${res.total} 台在线 agent 下发规则更新`)
      }
    } catch {
      message.error("同步到 agent 失败")
    } finally {
      setSyncingToAgents(false)
    }
  }

  const handleSyncNucleiLib = async () => {
    setSyncTplLoading(true)
    try {
      const res = await syncNucleiTemplatesLibrary()
      const verify = res.matched ? "" : `（校对：ES 实际 ${res.es_actual} 条）`
      message.success(`模板库已更新：${res.count} 条 (v${res.version})${verify}`)
      fetchNucleiTpls()
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "联网更新失败")
    } finally {
      setSyncTplLoading(false)
    }
  }

  const handleImportNucleiZip = async (file: File) => {
    setImportTplLoading(true)
    try {
      const res = await importNucleiTemplatesZip(file)
      const note = res.upgraded ? `（从 v${res.previous_version || "无"} 升级）` : ""
      message.success(`已导入：${res.count} 条模板 (v${res.version})${note}`)
      fetchNucleiTpls()
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "导入失败，请检查 zip")
    } finally {
      setImportTplLoading(false)
    }
    return false
  }

  const handleSyncNucleiTpl = async () => {
    setSyncingNucleiTpl(true)
    try {
      const res = await syncNucleiTemplates()
      if (res.total === 0) {
        message.warning("当前无在线 agent")
      } else {
        message.success(`已向 ${res.synced}/${res.total} 台在线 agent 下发 Nuclei 模板 (v${res.version})`)
      }
    } catch (e: any) {
      // 400 = 服务端未配置 NUCLEI_TEMPLATES_VERSION
      if (e?.response?.status === 400) {
        message.error("Nuclei 模板版本未配置：请在 Nacos 设置 NUCLEI_TEMPLATES_VERSION 与 NUCLEI_DOWNLOAD_BASE_URL")
      } else {
        message.error("同步 Nuclei 模板失败")
      }
    } finally {
      setSyncingNucleiTpl(false)
    }
  }

  const handleImport = async (file: File) => {
    setImporting(true)
    try {
      const res = await importRules(file)
      setVersion(res.version)
      setLastCount(res.count)
      message.success(`规则库已导入：${res.count} 条规则 (v${res.version})`)
      fetchRules()
    } catch {
      message.error("导入失败，请检查 zip 文件是否包含 rulepack.json")
    } finally {
      setImporting(false)
    }
    return false // 阻止 antd Upload 自动上传
  }

  const handleTabChange = (key: string) => {
    setActiveTab(key)
    // 只有规则类 tab（all/sys_vuln/baseline）才设 rules 分类；
    // detection / nuclei_templates 不是 rules 分类，避免触发无意义的 rules/list 请求。
    if (key === "all" || key === "sys_vuln" || key === "baseline") {
      setCategory(key === "all" ? "" : key)
      setPage(1)
    }
  }

  const handleSearch = (value: string) => {
    setQ(value)
    // page(1) 由 debounce useEffect 触发，避免这里重复设置
  }

  // V12 阶段 3.2: memoize columns（render 函数引用稳定组件作用域常量）
  const columns = useMemo(() => [
    { title: "规则 ID", dataIndex: "id", key: "id", width: 150, ellipsis: true },
    { title: "规则名称", dataIndex: "name", key: "name", ellipsis: true,
      render: (v: string) => <Tooltip title={v}>{v}</Tooltip> },
    { title: "CVE", dataIndex: "cve", key: "cve", width: 150, ellipsis: true,
      render: (v: string | null) => v ? <Tag>{v}</Tag> : <span style={{ color: "#999" }}>-</span> },
    { title: "分类", dataIndex: "category", key: "category", width: 120,
      render: (v: string) => {
        const c = CATEGORY_CONFIG[v]
        return c ? <Tag color={c.color}>{c.label}</Tag> : v
      }},
    { title: "严重等级", dataIndex: "severity", key: "severity", width: 100,
      render: (v: string) => {
        const s = SEVERITY_CONFIG[v]
        return s ? <Tag color={s.color}>{s.label}</Tag> : v
      }},
    { title: "检查类型", key: "check_type", width: 110,
      render: (_: unknown, r: RuleItem) => CHECK_TYPE_LABEL[r.check?.type] || r.check?.type || "-" },
    { title: "修复建议", dataIndex: "fix", key: "fix", ellipsis: true,
      render: (v: string) => <Tooltip title={v}><span style={{ color: "#555" }}>{v || "-"}</span></Tooltip> },
  ], [])

  return (
    <div>
      <Card title="规则管理" extra={
        <Space wrap>
          <Button icon={<ReloadOutlined />} onClick={() => { fetchVersion(); fetchRules() }} loading={loadingVer}>刷新</Button>
          <Button icon={<CloudSyncOutlined />} loading={syncingToAgents} onClick={handleSyncToAgents} title="强制下发当前规则到所有在线 agent">
            同步到 agent
          </Button>
          <Button icon={<ExperimentOutlined />} loading={syncingNucleiTpl} onClick={handleSyncNucleiTpl} title="下发 nuclei-templates 模板库到所有在线 agent（独立于漏洞规则）">
            同步 Nuclei 模板
          </Button>
          <Upload accept=".zip" showUploadList={false} beforeUpload={handleImport}>
            <Button icon={<UploadOutlined />} loading={importing}>离线导入</Button>
          </Upload>
          <Button icon={<QuestionCircleOutlined />} onClick={() => setImportHelpOpen(true)}>导入说明</Button>
          <Button type="primary" icon={<GlobalOutlined />} onClick={() => handleSync("nvd")} loading={syncingNvd}>
            联网更新(NVD/国外)
          </Button>
          <Button icon={<ApiOutlined />} onClick={() => handleSync("github")} loading={syncingGithub}>
            联网更新(GitHub/国内)
          </Button>
        </Space>
      }>
        <Descriptions bordered column={2} size="small" style={{ marginBottom: 16 }}>
          <Descriptions.Item label="当前版本">
            {version && version !== "0" ? <Tag color="blue">{version}</Tag> : <Spin size="small" />}
          </Descriptions.Item>
          <Descriptions.Item label="上次同步规则数">{lastCount !== null ? lastCount : (total || "-")}</Descriptions.Item>
          <Descriptions.Item label="数据源">
            <Tag color="green">NVD（国家漏洞数据库）</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="同步计划">每日 03:00 自动同步</Descriptions.Item>
          <Descriptions.Item label="规则分类" span={2}>
            <Tag color="red">漏洞扫描规则</Tag> 基于 CVE 的系统软件包漏洞检测
            <Tag color="blue" style={{ marginLeft: 8 }}>安全基线规则</Tag> 系统安全配置基线检查（SSH/密码策略/防火墙/审计等）
          </Descriptions.Item>
        </Descriptions>

        <Card size="small" title="规则分发机制" style={{ marginBottom: 16, background: "#f0f5ff" }}>
          <p style={{ fontSize: 13, color: "#666", marginBottom: 4 }}>
            <SafetyCertificateOutlined /> Agent 每次心跳上报规则版本，服务端比对后若版本落后则通过 WebSocket 下发 <Tag>rule_update</Tag> 命令（含规则包下载地址与 Ed25519 签名）。
          </p>
          <p style={{ fontSize: 13, color: "#666", marginBottom: 4 }}>
            规则包采用 Ed25519 签名（服务端私钥 + Agent 启动时拉取的公钥），Agent 验签失败时丢弃并上报。验签通过的热加载无需重启，立即生效。
          </p>
          <p style={{ fontSize: 13, color: "#666", marginBottom: 4 }}>
            上方 <Tag color="blue">离线导入</Tag> 直接上传 zip 压缩包（仅含 rules.json），服务端用同一私钥重新签名后入库；导入后可点 <Tag color="cyan">同步到 agent</Tag> 强制下发到所有在线主机。
          </p>
          <p style={{ fontSize: 13, color: "#666", marginBottom: 4 }}>
            <Tag color="purple">同步 Nuclei 模板</Tag> 是独立功能：下发 projectdiscovery nuclei-templates 模板包到所有在线 agent 的 <Text code>/opt/secagent/templates</Text>（nuclei 扫描引擎用 <Text code>-t</Text> 读取）。模板包从内网下载站拉取，版本由 Nacos <Text code>NUCLEI_TEMPLATES_VERSION</Text> 控制，与上面的漏洞规则包互不影响。
          </p>
          <p style={{ fontSize: 13, color: "#666" }}>
            首次安装的 agent 在 enroll 阶段会从服务端响应里读到 server_public_key 并写入 <Text code>/etc/secagent/config.json</Text>（参见 install.sh + agent/cmd/agent/main.go）。
          </p>
        </Card>

        <Tabs activeKey={activeTab} onChange={handleTabChange} items={[
          { key: "all", label: "全部" },
          { key: "sys_vuln", label: "漏洞扫描规则" },
          { key: "baseline", label: "安全基线规则" },
          { key: "detection", label: "检测规则" },
          { key: "nuclei_templates", label: "Nuclei 模板库" },
        ]} />

        {activeTab === "nuclei_templates" ? (
          <div>
            <Space style={{ marginBottom: 16, justifyContent: "space-between", width: "100%" }}>
              <Space wrap>
                <Select
                  allowClear
                  placeholder="分类"
                  style={{ width: 150 }}
                  value={nucleiCategory}
                  onChange={(v) => { setNucleiCategory(v); setNucleiPage(1) }}
                  options={[
                    { value: "cves", label: "cves" },
                    { value: "exposures", label: "exposures" },
                    { value: "misconfigurations", label: "misconfigurations" },
                    { value: "vulnerabilities", label: "vulnerabilities" },
                    { value: "workflows", label: "workflows" },
                    { value: "dns", label: "dns" },
                    { value: "http", label: "http" },
                    { value: "network", label: "network" },
                    { value: "ssl", label: "ssl" },
                    { value: "takeovers", label: "takeovers" },
                    { value: "technologies", label: "technologies" },
                  ]}
                />
                <Input
                  allowClear
                  placeholder="搜索模板 ID / 名称 / 路径"
                  prefix={<SearchOutlined />}
                  value={nucleiQ}
                  onChange={(e) => setNucleiQ(e.target.value)}
                  style={{ width: 280 }}
                />
                <Button onClick={fetchNucleiTpls} icon={<ReloadOutlined />} loading={nucleiLoading}>刷新</Button>
              </Space>
              <Space>
                <Button type="primary" icon={<GlobalOutlined />} loading={syncTplLoading} onClick={handleSyncNucleiLib} title="从内网下载站拉取 nuclei-templates 包并入库 Nacos">
                  联网更新
                </Button>
                <Upload accept=".zip" showUploadList={false} beforeUpload={handleImportNucleiZip}>
                  <Button icon={<UploadOutlined />} loading={importTplLoading}>导入 zip</Button>
                </Upload>
              </Space>
            </Space>
            <Descriptions bordered column={2} size="small" style={{ marginBottom: 12 }}>
              <Descriptions.Item label="模板库版本">{nucleiVer ? <Tag color="blue">{nucleiVer}</Tag> : "-"}</Descriptions.Item>
              <Descriptions.Item label="模板总数">{nucleiTotal}</Descriptions.Item>
            </Descriptions>
            <Table
              dataSource={nucleiTpls}
              rowKey="path"
              loading={nucleiLoading}
              size="small"
              pagination={{
                current: nucleiPage,
                pageSize: nucleiPageSize,
                total: nucleiTotal,
                showSizeChanger: true,
                pageSizeOptions: ["20", "50", "100"],
                showTotal: (t) => `共 ${t} 条`,
                onChange: (p, ps) => { setNucleiPage(p); setNucleiPageSize(ps) },
              }}
              columns={[
                { title: "模板 ID", dataIndex: "template_id", key: "template_id", width: 200, ellipsis: true,
                  render: (v: string) => v ? <code style={{ fontSize: 12 }}>{v}</code> : <span style={{ color: "#bbb" }}>-</span> },
                { title: "名称", dataIndex: "name", key: "name", ellipsis: true,
                  render: (v: string) => <Tooltip title={v}>{v || "-"}</Tooltip> },
                { title: "分类", dataIndex: "category", key: "category", width: 130,
                  render: (v: string) => <Tag color="blue">{v}</Tag> },
                { title: "严重等级", dataIndex: "severity", key: "severity", width: 100,
                  render: (v: string) => {
                    const s = SEVERITY_CONFIG[v]
                    return s ? <Tag color={s.color}>{s.label}</Tag> : (v ? <Tag>{v}</Tag> : <span style={{ color: "#bbb" }}>-</span>)
                  }},
                { title: "路径", dataIndex: "path", key: "path", ellipsis: true,
                  render: (v: string) => <Tooltip title={v}><code style={{ fontSize: 12, color: "#888" }}>{v}</code></Tooltip> },
                { title: "操作", key: "action", width: 90,
                  render: (_: unknown, r: NucleiTemplateMeta) => (
                    <Button size="small" type="link" icon={<EyeOutlined />} onClick={() => setViewerPath(r.path)}>查看</Button>
                  )},
              ]}
              locale={{ emptyText: "暂无模板，请点击「联网更新」或「导入 zip」" }}
            />
          </div>
        ) : (
        <>
        <Space style={{ marginBottom: 16 }}>
          <Input
            allowClear
            placeholder="搜索规则名称 / CVE"
            prefix={<SearchOutlined />}
            value={q}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: 260 }}
          />
          <Select
            allowClear
            placeholder="严重等级"
            style={{ width: 140 }}
            value={severity}
            options={Object.entries(SEVERITY_CONFIG).map(([k, v]) => ({ label: v.label, value: k }))}
            onChange={(v) => { setSeverity(v); setPage(1) }}
          />
        </Space>

        {activeTab === "detection" ? (
          <div>
            {sigmaSummary && (
              <Card size="small" style={{ marginBottom: 16 }}>
                <Space size="large" wrap>
                  <span><b>已导入:</b> {sigmaSummary.accepted} 条</span>
                  <span><b>跳过:</b> {sigmaSummary.skipped} 条</span>
                  <span><b>导入时间:</b> {sigmaSummary.imported_at || "—"}</span>
                </Space>
                <div style={{ marginTop: 8 }}>
                  <Space size="large" wrap>
                    {Object.entries(sigmaSummary.by_category || {}).map(([k, v]) => (
                      <Tag key={`cat-${k}`} color="blue">{k}: {v}</Tag>
                    ))}
                    {Object.entries(sigmaSummary.by_os || {}).map(([k, v]) => (
                      <Tag key={`os-${k}`} color="geekblue">{k}: {v}</Tag>
                    ))}
                    {Object.entries(sigmaSummary.by_level || {}).map(([k, v]) => (
                      <Tag key={`lvl-${k}`} color="purple">{k}: {v}</Tag>
                    ))}
                  </Space>
                </div>
              </Card>
            )}

            <Space style={{ marginBottom: 16 }} wrap>
              <Select
                allowClear
                placeholder="分类"
                style={{ width: 160 }}
                value={sigmaCategory}
                onChange={(v) => setSigmaCategory(v)}
                options={[
                  { value: "process_creation", label: "进程创建" },
                  { value: "file_event", label: "文件事件" },
                  { value: "network_connection", label: "网络连接" },
                  { value: "dns_query", label: "DNS 查询" },
                  { value: "image_load", label: "镜像加载" },
                ]}
              />
              <Select
                allowClear
                placeholder="操作系统"
                style={{ width: 130 }}
                value={sigmaOs}
                onChange={(v) => setSigmaOs(v)}
                options={[
                  { value: "linux", label: "Linux" },
                  { value: "macos", label: "macOS" },
                  { value: "windows", label: "Windows" },
                ]}
              />
              <Select
                allowClear
                placeholder="严重等级"
                style={{ width: 140 }}
                value={sigmaLevel}
                onChange={(v) => setSigmaLevel(v)}
                options={Object.entries(SEVERITY_CONFIG).map(([k, v]) => ({ label: v.label, value: k }))}
              />
              <Select
                allowClear
                placeholder="检测器支持"
                style={{ width: 140 }}
                value={sigmaDetectorOnly === null ? undefined : sigmaDetectorOnly}
                onChange={(v) => setSigmaDetectorOnly(v === undefined ? null : v)}
                options={[
                  { value: true, label: "已支持" },
                  { value: false, label: "暂不支持" },
                ]}
              />
              <Button onClick={fetchSigma} icon={<ReloadOutlined />}>刷新</Button>
            </Space>

            <Table<SigmaRuleItem>
              dataSource={sigmaRules}
              rowKey="rule_id"
              loading={sigmaLoading}
              pagination={{ defaultPageSize: 20, showSizeChanger: true, pageSizeOptions: ["20", "50", "100"], showTotal: (t) => `共 ${t} 条` }}
              columns={[
                { title: "规则 ID", dataIndex: "rule_id", width: 200,
                  render: (v: string) => <code>{v}</code> },
                { title: "标题", dataIndex: "title", ellipsis: true },
                { title: "等级", dataIndex: "level", width: 90,
                  render: (v: string) => {
                    const cfg = SEVERITY_CONFIG[v] || { color: "default", label: v }
                    return <Tag color={cfg.color}>{cfg.label}</Tag>
                  } },
                { title: "适用 OS", dataIndex: "applicable_os", width: 150,
                  render: (os: string[]) => (
                    <Space size={2} wrap>{(os || []).map((o) => <Tag key={o}>{o}</Tag>)}</Space>
                  ) },
                { title: "MITRE ATT&CK", dataIndex: "mitre_techniques", width: 200,
                  render: (ts: string[]) => (
                    <Space size={2} wrap>{(ts || []).map((t) => <Tag key={t} color="magenta">{t}</Tag>)}</Space>
                  ) },
                { title: "检测器", dataIndex: "detector_supported", width: 100,
                  render: (v: boolean) => v ? <Tag color="green">✓</Tag> : <Tag color="default">—</Tag> },
              ]}
              locale={{ emptyText: "未导入 Sigma 规则,或当前筛选无匹配" }}
            />

            {sigmaSummary && sigmaSummary.skipped_reasons && sigmaSummary.skipped_reasons.length > 0 && (
              <Card size="small" style={{ marginTop: 16 }} title={`跳过原因 (${sigmaSummary.skipped_reasons.length})`}>
                {sigmaSummary.skipped_reasons.map((s, i) => (
                  <div key={i} style={{ marginBottom: 4 }}>
                    <code style={{ fontSize: 12 }}>{s.path}</code>
                    <span style={{ marginLeft: 8, color: "#999" }}>{s.reason}</span>
                  </div>
                ))}
              </Card>
            )}
          </div>
        ) : (
          <Table
            dataSource={rules}
            columns={columns}
            rowKey="id"
            loading={loading}
            pagination={{
              current: page,
              pageSize,
              total,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => { setPage(p); setPageSize(ps) },
            }}
            locale={{ emptyText: "暂无规则，请点击「联网更新」或「离线导入」" }}
          />
        )}
        </>
        )}
      </Card>

      <NucleiTemplateViewer path={viewerPath} onClose={() => setViewerPath(null)} />

      <Modal title="离线导入说明" open={importHelpOpen} onCancel={() => setImportHelpOpen(false)} footer={null} width={620}>
        <Paragraph>
          <Text strong>适用场景：</Text>联网同步失败（国内访问 NVD 超时）、或需导入自定义/离线规则库时使用。支持三种数据来源，程序自动识别格式。
        </Paragraph>

        <Paragraph>
          <Text strong>来源 1：本系统 rulepack.json（自建/转换）</Text>
          <br />
          手写或从其他来源转换成系统格式的规则包。zip 内含 <Text code>rulepack.json</Text>。
          <pre style={{ background: "#f5f5f5", padding: 12, borderRadius: 6, fontSize: 12, marginTop: 8, overflow: "auto" }}>{`{
  "rules": [
    {
      "id": "CVE-2024-1234", "category": "sys_vuln", "cve": "CVE-2024-1234",
      "name": "openssl: 存在缓冲区溢出漏洞", "severity": "high",
      "check": {"type": "package_version", "name": "openssl", "op": "lt", "value": "1.1.1k"},
      "fix": "升级 openssl 到 1.1.1k 及以上"
    }
  ]
}`}</pre>
        </Paragraph>

        <Paragraph>
          <Text strong>来源 2：NVD JSON 导出</Text>
          <br />
          在能联网的机器上调用 NVD API 保存 JSON，或从
          <a href="https://nvd.nist.gov/vuln/data-feeds" target="_blank" rel="noreferrer"> nvd.nist.gov/vuln/data-feeds</a>
          下载。zip 内含 NVD 原始 JSON（<Text code>vulnerabilities</Text> 数组），系统自动解析 CPE 转规则。
          <br />
          <Text type="secondary" style={{ fontSize: 12 }}>示例命令（联网机器执行后打包成 zip）：<br />
          <Text code>curl -H "apiKey: YOUR_KEY" "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000" -o nvd.json && zip nvd.zip nvd.json</Text>
          </Text>
        </Paragraph>

        <Paragraph>
          <Text strong>来源 3：GitHub advisory-database 离线包</Text>
          <br />
          从 <a href="https://github.com/github/advisory-database" target="_blank" rel="noreferrer">github/advisory-database</a>
          下载仓库 zip（Code → Download ZIP），直接上传。zip 内含多个 <Text code>GHSA-*.json</Text>，系统自动解析 affected 包信息转规则。
          <br />
          <Text type="secondary" style={{ fontSize: 12 }}>也可用 git clone 后打包 advisories 目录：<br />
          <Text code>git clone https://github.com/github/advisory-database && cd advisory-database && zip -r adv.zip advisories</Text>
          </Text>
        </Paragraph>

        <Paragraph>
          <Text strong>字段说明（rulepack 格式）：</Text>
          <ul>
            <li><Text code>id</Text>：规则ID，CVE 规则用 CVE 号，基线规则用 BL-xxx</li>
            <li><Text code>category</Text>：<Text code>sys_vuln</Text>(漏洞) 或 <Text code>baseline</Text>(基线)</li>
            <li><Text code>check.type</Text>：<Text code>package_version</Text>(包版本) / <Text code>kernel_version</Text>(内核) / <Text code>config_check</Text>(配置文件)</li>
            <li><Text code>severity</Text>：critical / high / medium / low / info</li>
          </ul>
        </Paragraph>
        <Paragraph type="secondary">
          导入时系统会用服务端密钥重新签名，无需自行签名。导入后新规则立即生效，可通过「同步到 agent」下发到所有在线 agent。
        </Paragraph>
      </Modal>
    </div>
  )
}
