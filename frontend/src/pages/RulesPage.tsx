import { useEffect, useState, useCallback } from "react"
import { Card, Button, Descriptions, Tag, message, Space, Spin, Table, Input, Select, Tabs, Tooltip, Upload, Modal, Typography } from "antd"
import { SafetyCertificateOutlined, ReloadOutlined, SearchOutlined, UploadOutlined, QuestionCircleOutlined, CloudSyncOutlined, GlobalOutlined, ApiOutlined } from "@ant-design/icons"
import { listRules, getRuleVersion, syncRules, importRules, syncRulesToAgents, type RuleItem } from "../api/client"

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

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedQ(q)
      setPage(1)
    }, 300)
    return () => clearTimeout(t)
  }, [q])

  const fetchVersion = async () => {
    setLoadingVer(true)
    try {
      const res = await getRuleVersion()
      setVersion(res.version)
    } catch { /* ignore */ }
    finally { setLoadingVer(false) }
  }

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
    setCategory(key === "all" ? "" : key)
    setPage(1)
  }

  const handleSearch = (value: string) => {
    setQ(value)
    // page(1) 由 debounce useEffect 触发，避免这里重复设置
  }

  const columns = [
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
  ]

  return (
    <div>
      <Card title="规则管理" extra={
        <Space wrap>
          <Button icon={<ReloadOutlined />} onClick={() => { fetchVersion(); fetchRules() }} loading={loadingVer}>刷新</Button>
          <Button icon={<CloudSyncOutlined />} loading={syncingToAgents} onClick={handleSyncToAgents} title="强制下发当前规则到所有在线 agent">
            同步到 agent
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
          <p style={{ fontSize: 13, color: "#666" }}>
            首次安装的 agent 在 enroll 阶段会从服务端响应里读到 server_public_key 并写入 <Text code>/etc/secagent/config.json</Text>（参见 install.sh + agent/cmd/agent/main.go）。
          </p>
        </Card>

        <Tabs activeKey={activeTab} onChange={handleTabChange} items={[
          { key: "all", label: "全部" },
          { key: "sys_vuln", label: "漏洞扫描规则" },
          { key: "baseline", label: "安全基线规则" },
        ]} />

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
      </Card>

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
