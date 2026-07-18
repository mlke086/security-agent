import { useEffect, useState } from "react"
import { Card, Button, Form, InputNumber, Select, message, Table, Tag, Typography, Space, Popconfirm, Tooltip } from "antd"
import { PlusOutlined, CopyOutlined, ReloadOutlined, CloudServerOutlined } from "@ant-design/icons"
import type { Host } from "../api/client"
import {
  createEnrollToken,
  getConsoleUrl,
  getInstallHelper,
  getInstallScript,
  listHosts,
  deleteHost,
} from "../api/client"

const { Text } = Typography

function getStatusColor(status: string) {
  switch (status) {
    case "online": return "green"
    case "offline": return "red"
    default: return "default"
  }
}

function getStatusLabel(status: string) {
  switch (status) {
    case "online": return "在线"
    case "offline": return "离线"
    case "decommissioned": return "已下线"
    default: return status
  }
}

export default function HostOnboardPage() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(false)
  const [showToken, setShowToken] = useState(false)
  const [linuxScript, setLinuxScript] = useState("")
  const [windowsScript, setWindowsScript] = useState("")
  const [linuxHelper, setLinuxHelper] = useState("")
  const [windowsHelper, setWindowsHelper] = useState("")
  const [selectedOS, setSelectedOS] = useState<"linux" | "windows">("linux")
  const [currentToken, setCurrentToken] = useState("")
  const [consoleBaseUrl, setConsoleBaseUrl] = useState<string>("")

  // Resolve the canonical console URL once on mount so the install
  // snippets point at the deployable URL (not whatever the operator's
  // browser happens to hit -- reverse proxy / ingress could differ).
  useEffect(() => {
    let alive = true
    getConsoleUrl().then((u) => { if (alive) setConsoleBaseUrl(u) })
    return () => { alive = false }
  }, [])

  const fetchHosts = async () => {
    setLoading(true)
    try { const res = await listHosts(); setHosts(res.items) }
    catch { message.error("加载主机列表失败") }
    finally { setLoading(false) }
  }

  const handleCreateToken = async (values: { group?: string; ttl_hours: number; uses: number }) => {
    try {
      const res = await createEnrollToken(values.group || null, values.ttl_hours, values.uses)
      setCurrentToken(res.token)
      // Pre-warm install + helper endpoints (validate token + cache). We pull
      // both the full script and the operator-friendly two-step snippet so the
      // operator can either copy the snippet (recommended) or inspect the
      // script before running it.
      const linux = await getInstallScript(res.token, "linux"); setLinuxScript(linux)
      const windows = await getInstallScript(res.token, "windows"); setWindowsScript(windows)
      const linuxHelper = await getInstallHelper(res.token, "linux"); setLinuxHelper(linuxHelper)
      const windowsHelper = await getInstallHelper(res.token, "windows"); setWindowsHelper(windowsHelper)
      setShowToken(true)
    } catch { message.error("生成令牌失败") }
  }

  const copyToClipboard = (text: string, label: string) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        () => message.success(label + " 已复制到剪贴板"),
        () => {
          // Clipboard API failed, try fallback
          fallbackCopy(text)
          message.success(label + " 已复制到剪贴板")
        }
      )
    } else {
      fallbackCopy(text)
      message.success(label + " 已复制到剪贴板")
    }
  }

  const fallbackCopy = (text: string) => {
    const ta = document.createElement("textarea")
    ta.value = text
    ta.style.position = "fixed"
    ta.style.left = "-9999px"
    ta.style.top = "-9999px"
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    document.execCommand("copy")
    document.body.removeChild(ta)
  }

  const handleCopyToken = () => copyToClipboard(currentToken, "令牌")
  const handleCopy = () => {
    // Prefer the server-side helper snippet (URL already quoted, two-step flow).
    // Fall back to a client-built snippet if the helper call failed.
    const helper = selectedOS === "linux" ? linuxHelper : windowsHelper
    if (helper && helper.trim()) {
      copyToClipboard(helper, "安装命令")
      return
    }
    // Prefer the configured console URL from the backend; fall back to the
    // current page origin (which already includes any reverse-proxy host/port)
    // -- do NOT hardcode ":8000" because the console may be behind nginx,
    // k8s ingress, etc.
    const base = consoleBaseUrl || `${window.location.origin}`
    const installUrl =
      selectedOS === "linux"
        ? `${base}/api/v1/agents/install?token=${currentToken}&os=linux`
        : `${base}/api/v1/agents/install?token=${currentToken}&os=windows`
    const cmd =
      selectedOS === "linux"
        ? // Two-step: SINGLE LINE so it copy-pastes cleanly. No `\\n`
          // continuations -- they break when pasted into a real terminal
          // because bash sees `&&` on the next line as a separate command.
          `curl -fsSL "${installUrl}" -o secagent-install.sh && chmod +x secagent-install.sh && sudo bash secagent-install.sh`
        : // PowerShell two-step (multi-line is fine for PowerShell).
          `Invoke-WebRequest -Uri "${installUrl}" -OutFile secagent-install.ps1\nUnblock-File .\\secagent-install.ps1\n.\\secagent-install.ps1`
    copyToClipboard(cmd, "安装命令")
  }

  const handleDelete = async (agentId: string) => {
    try { await deleteHost(agentId); message.success("主机已下线"); fetchHosts() }
    catch { message.error("操作失败") }
  }

  const columns = [
    { title: "主机名", dataIndex: "hostname", key: "hostname" },
    { title: "IP", dataIndex: "ip", key: "ip" },
    { title: "OS", dataIndex: "os", key: "os", render: (v: string) => <Tag>{v}</Tag> },
    { title: "架构", dataIndex: "arch", key: "arch" },
    { title: "状态", dataIndex: "status", key: "status", render: (v: string) => <Tag color={getStatusColor(v)}>{getStatusLabel(v)}</Tag> },
    { title: "Agent版本", dataIndex: "agent_version", key: "agent_version" },
    { title: "规则版本", dataIndex: "rule_version", key: "rule_version" },
    { title: "组", dataIndex: "group", key: "group", render: (v: string | null) => v || "-" },
    { title: "操作", key: "action", render: (_: unknown, r: Host) => (
      <Popconfirm title="确定下线该主机?" onConfirm={() => handleDelete(r.agent_id)}>
        <Button size="small" danger>下线</Button>
      </Popconfirm>
    )},
  ]

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ReloadOutlined />} onClick={fetchHosts} loading={loading}>刷新</Button>
      </Space>

      <Card title="纳管令牌" id="token-form" style={{ marginBottom: 24 }}>
        <Form layout="inline" onFinish={handleCreateToken} initialValues={{ ttl_hours: 24, uses: 1 }}>
          <Form.Item name="group" label="组">
            <Select style={{ width: 120 }} allowClear placeholder="默认">
              <Select.Option value="prod">生产</Select.Option>
              <Select.Option value="test">测试</Select.Option>
              <Select.Option value="dev">开发</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="ttl_hours" label="TTL(h)">
            <InputNumber min={1} max={720} style={{ width: 100 }} />
          </Form.Item>
          <Form.Item name="uses" label="次数">
            <InputNumber min={1} max={100} style={{ width: 100 }} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" icon={<PlusOutlined />} htmlType="submit">生成令牌</Button>
          </Form.Item>
        </Form>

        {showToken && currentToken && (
          <Card size="small" style={{ marginTop: 16, background: "#f6ffed" }}>
            <Space direction="vertical" style={{ width: "100%" }}>
              <Text strong>令牌已生成，请在目标主机执行：</Text>
              <Space>
                <Button size="small" icon={<CopyOutlined />} onClick={handleCopyToken}>复制令牌</Button>
                <Button size="small" type={selectedOS === "linux" ? "primary" : "default"} onClick={() => setSelectedOS("linux")}>Linux</Button>
                <Button size="small" type={selectedOS === "windows" ? "primary" : "default"} onClick={() => setSelectedOS("windows")}>Windows</Button>
              </Space>
              <pre style={{ background: "#1e1e1e", color: "#d4d4d4", padding: 12, borderRadius: 6, overflow: "auto", fontSize: 13, fontFamily: "monospace" }}>
{(selectedOS === "linux" ? linuxHelper : windowsHelper) ||
  // Fallback: build the two-step snippet client-side if the helper fetch failed.
  // Linux is SINGLE LINE (no `\\n`); Windows is multi-line (PowerShell).
  (selectedOS === "linux"
    ? `curl -fsSL "${(consoleBaseUrl || window.location.origin)}/api/v1/agents/install?token=${currentToken}&os=linux" -o secagent-install.sh && chmod +x secagent-install.sh && sudo bash secagent-install.sh`
    : `Invoke-WebRequest -Uri "${(consoleBaseUrl || window.location.origin)}/api/v1/agents/install?token=${currentToken}&os=windows" -OutFile secagent-install.ps1\nUnblock-File .\\secagent-install.ps1\n.\\secagent-install.ps1`)}
              </pre>
              <Space>
                <Button icon={<CopyOutlined />} onClick={handleCopy}>复制安装命令</Button>
                <Tooltip title="预览完整脚本（推荐先看再执行）">
                  <Button size="small" onClick={selectedOS === "linux"
                    ? () => copyToClipboard(linuxScript, "Linux 脚本")
                    : () => copyToClipboard(windowsScript, "Windows 脚本")}>
                    复制完整脚本
                  </Button>
                </Tooltip>
              </Space>
            </Space>
          </Card>
        )}
      </Card>

      <Card title={`主机列表 (${hosts.length})`}>
        <Table dataSource={hosts} columns={columns} rowKey="agent_id" loading={loading} pagination={{ pageSize: 20 }}
          locale={{ emptyText: <div style={{ padding: 40 }}><CloudServerOutlined style={{ fontSize: 48, color: "#ccc" }} /><div style={{ marginTop: 16, color: "#999" }}>暂无纳管主机</div></div> }}
        />
      </Card>
    </div>
  )
}
