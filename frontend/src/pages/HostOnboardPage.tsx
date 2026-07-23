import { useEffect, useState } from "react"
import { Card, Button, Form, InputNumber, Select, message, Table, Tag, Typography, Space, Popconfirm, Tooltip, Modal, Input, Empty, Switch } from "antd"
import { PlusOutlined, CopyOutlined, ReloadOutlined, CloudServerOutlined, DeleteOutlined, TeamOutlined, CloudUploadOutlined } from "@ant-design/icons"
import type { Host, HostGroup } from "../api/client"
import {
  createEnrollToken,
  getConsoleUrl,
  getInstallHelper,
  getInstallScript,
  listHosts,
  listGroups,
  createGroup,
  deleteGroup,
  updateHostGroup,
  deleteHost,
  upgradeAgent,
  getAgentUpgradeStatus,
  type AgentUpgradeStatus,
} from "../api/client"

const { Text } = Typography

function getStatusColor(status: string) {
  switch (status) {
    case "online": return "green"
    case "offline": return "red"
    case "decommissioned": return "default"  // gray -- render below in a muted style
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

  const [groups, setGroups] = useState<HostGroup[]>([])
  const [groupFilter, setGroupFilter] = useState<string | undefined>(undefined)
  const [groupModalOpen, setGroupModalOpen] = useState(false)
  // 需求1.3：主机列表搜索（前端过滤，debounce 300ms）
  const [hostSearch, setHostSearch] = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [groupForm] = Form.useForm()
  // P1-UX (2026-07-22): default hides soft-deleted hosts so clicking
  // 删除 actually makes them disappear. Operators can flip this on to
  // see + physically purge old rows.
  const [showDecommissioned, setShowDecommissioned] = useState(false)
  const [upgradeById, setUpgradeById] = useState<Record<string, AgentUpgradeStatus["upgrade"] | undefined>>({})
  const [upgrading, setUpgrading] = useState<Record<string, boolean>>({})

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(hostSearch.trim().toLowerCase()), 300)
    return () => clearTimeout(t)
  }, [hostSearch])

  // Resolve the canonical console URL once on mount so the install
  // snippets point at the deployable URL (not whatever the operator's
  // browser happens to hit -- reverse proxy / ingress could differ).
  useEffect(() => {
    let alive = true
    getConsoleUrl().then((u) => { if (alive) setConsoleBaseUrl(u) })
    return () => { alive = false }
  }, [])

  // P1-FE-04 (2026-07-20): fetch hosts on mount so the table isn't
  // empty until the operator clicks the Refresh button.
  useEffect(() => {
    let alive = true
    listHosts({ include_decommissioned: showDecommissioned })
      .then((res) => { if (alive) setHosts(res.items) })
      .catch(() => { if (alive) message.error("加载主机列表失败") })
    fetchGroups()
    return () => { alive = false }
  }, [showDecommissioned])

  // P2-UPGRADE-03 (2026-07-22): refresh upgrade status for every online
  // host so the badge reflects the latest server-side state.
  useEffect(() => {
    if (!hosts) return
    hosts.forEach((h) => { if (h.status !== "decommissioned") void refreshUpgrade(h.agent_id) })
  }, [hosts])

  const refreshHostsData = async () => {
    setLoading(true)
    try {
      const res = await listHosts(
        groupFilter
          ? { group: groupFilter, include_decommissioned: showDecommissioned }
          : { include_decommissioned: showDecommissioned },
      )
      setHosts(res.items)
    }
    catch { message.error("加载主机列表失败") }
    finally { setLoading(false) }
  }

  const refreshUpgrade = async (agentId: string) => {
    try {
      const r = await getAgentUpgradeStatus(agentId)
      setUpgradeById((prev) => ({ ...prev, [agentId]: r.upgrade }))
    } catch {
      setUpgradeById((prev) => ({ ...prev, [agentId]: undefined }))
    }
  }

  const handleUpgrade = async (agent: Host) => {
    if (upgrading[agent.agent_id]) return
    setUpgrading((prev) => ({ ...prev, [agent.agent_id]: true }))
    try {
      const r = await upgradeAgent(agent.agent_id)
      if (r.delivered) {
        message.success(`?? ${agent.hostname} ???? ${r.version} ??`)
      } else {
        message.warning("???????????????????????")
      }
      await refreshUpgrade(agent.agent_id)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      message.error(detail || "????")
    } finally {
      setUpgrading((prev) => ({ ...prev, [agent.agent_id]: false }))
    }
  }

    const fetchHosts = async () => {
    await refreshHostsData()
    // 需求2：点刷新主机列表时，隐藏令牌展示（令牌是一次性敏感凭证，展示后即应隐藏）
    setShowToken(false)
    setCurrentToken("")
  }

  const fetchGroups = async () => {
    try {
      const res = await listGroups()
      setGroups(res.items || [])
    } catch { /* 组列表加载失败不阻断主流程 */ }
  }

  // 主机列表与组筛选联动：切换筛选时重新拉取
  useEffect(() => {
    let alive = true
    setLoading(true)
    listHosts(groupFilter ? { group: groupFilter, include_decommissioned: showDecommissioned } : { include_decommissioned: showDecommissioned })
      .then((res) => { if (alive) setHosts(res.items) })
      .catch(() => { if (alive) message.error("加载主机列表失败") })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [groupFilter, showDecommissioned])

  const handleCreateToken = async (values: { group?: string; ttl_hours: number; uses: number }) => {
    try {
      const res = await createEnrollToken(values.group || null, values.ttl_hours, values.uses)
      setCurrentToken(res.token)
      // P2-12 修复：先展示 token（已建成功），预热 4 个请求并行发起 + allSettled，
      // 任一失败仅 warn 不影响 token 展示（原先串行 await 任一失败会进 catch
      // 显示"生成令牌失败"，让用户误以为没建成、丢失已建 token）。
      setShowToken(true)
      const results = await Promise.allSettled([
        getInstallScript(res.token, "linux"),
        getInstallScript(res.token, "windows"),
        getInstallHelper(res.token, "linux"),
        getInstallHelper(res.token, "windows"),
      ])
      if (results[0].status === "fulfilled") setLinuxScript(results[0].value)
      if (results[1].status === "fulfilled") setWindowsScript(results[1].value)
      if (results[2].status === "fulfilled") setLinuxHelper(results[2].value)
      if (results[3].status === "fulfilled") setWindowsHelper(results[3].value)
      const failed = results.filter((r) => r.status === "rejected").length
      if (failed > 0) {
        message.warning(`令牌已生成，但 ${failed} 个安装命令预拉失败，可手动复制安装命令`)
      }
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
    try { await deleteHost(agentId); message.success("主机已下线"); refreshHostsData() }
    catch { message.error("操作失败") }
  }

  const handlePurgeHost = async (agentId: string) => {
    // 需求1.4：物理删除已下线主机（purge=true）
    try {
      await deleteHost(agentId, true)
      message.success("主机已删除")
      refreshHostsData()
    } catch (e: any) {
      const detail = e?.response?.data?.detail
      message.error(detail || "删除失败")
    }
  }

  const handleChangeGroup = async (agentId: string, group: string | null) => {
    try {
      await updateHostGroup(agentId, group)
      message.success("已更改所属组")
      // 需求1.2：切换组后同时刷新主机列表和组列表（组 member_count 需更新，
      // 否则立即删原组会用旧 count 误判"还存在主机"）。用 refreshHostsData 不清令牌。
      await Promise.all([refreshHostsData(), fetchGroups()])
    } catch { message.error("更改组失败") }
  }

  const handleCreateGroup = async () => {
    try {
      const v = await groupForm.validateFields()
      await createGroup(v.name.trim(), v.description || "")
      message.success("主机组已创建")
      setGroupModalOpen(false)
      groupForm.resetFields()
      fetchGroups()
    } catch (e: any) {
      if (e?.errorFields) return // 表单校验失败，不提示
      message.error("创建组失败")
    }
  }

  const handleDeleteGroup = async (name: string) => {
    // 需求1.2：去掉前端 member_count 拦截（旧 state 会误判），让服务端 409 兜底。
    try {
      await deleteGroup(name)
      message.success("主机组已删除")
      fetchGroups()
    } catch (e: any) {
      const detail = e?.response?.data?.detail
      if (detail) message.error(detail)
      else message.error("删除组失败")
    }
  }

  const groupOptions = groups.map((g) => ({ label: g.name, value: g.name }))

  // 需求1.3：按 hostname/ip/agent_id/os 前端过滤
  const filteredHosts = debouncedSearch
    ? hosts.filter((h) =>
        (h.hostname || "").toLowerCase().includes(debouncedSearch) ||
        (h.ip || "").toLowerCase().includes(debouncedSearch) ||
        (h.agent_id || "").toLowerCase().includes(debouncedSearch) ||
        (h.os || "").toLowerCase().includes(debouncedSearch)
      )
    : hosts

  const columns = [
    { title: "主机名", dataIndex: "hostname", key: "hostname" },
    { title: "IP", dataIndex: "ip", key: "ip" },
    { title: "OS", dataIndex: "os", key: "os", render: (v: string) => <Tag>{v}</Tag> },
    { title: "架构", dataIndex: "arch", key: "arch" },
    { title: "状态", dataIndex: "status", key: "status", render: (v: string) => <Tag color={getStatusColor(v)}>{getStatusLabel(v)}</Tag> },
    { title: "Agent版本", dataIndex: "agent_version", key: "agent_version" },
    { title: "规则版本", dataIndex: "rule_version", key: "rule_version" },
    { title: "组", key: "group", render: (_: unknown, r: Host) => (
      <Select
        size="small"
        style={{ width: 140 }}
        allowClear
        placeholder="未分组"
        value={r.group || undefined}
        options={groupOptions}
        onChange={(v) => handleChangeGroup(r.agent_id, v ?? null)}
      />
    )},
    { title: "操作", key: "action", render: (_: unknown, r: Host) => (
    <Space size={4}>
      {r.status !== "decommissioned" && (
        <Button
          size="small"
          icon={<CloudUploadOutlined />}
          loading={upgrading[r.agent_id]}
          onClick={() => handleUpgrade(r)}
        >
          升级
        </Button>
      )}
      {r.status === "decommissioned" ? (
        <Popconfirm title="确定物理删除该主机?" description="删除后不可恢复" onConfirm={() => handlePurgeHost(r.agent_id)}>
          <Button size="small" danger>删除</Button>
        </Popconfirm>
      ) : (
        <Popconfirm title="确定下线该主机?" onConfirm={() => handleDelete(r.agent_id)}>
          <Button size="small" danger>下线</Button>
        </Popconfirm>
      )}
    </Space>
  )},
  { title: "升级状态", key: "upgrade", width: 170, render: (_: unknown, r: Host) => {
    const u = upgradeById[r.agent_id]
    if (!u || u.state === "idle") return <span style={{ color: "#999" }}>—</span>
    const stateMap: Record<string, { color: string; label: string }> = {
      sent: { color: "blue", label: "已下发升级" },
      restarting: { color: "gold", label: "Agent 重启中" },
      confirmed: { color: "green", label: `升级完成（${u.current_version || ""}）` },
      failed: { color: "red", label: "升级失败" },
      queued_for_delivery: { color: "default", label: "主机离线，待重连" },
    }
    const meta = stateMap[u.state] || { color: "default", label: u.state }
    return (
      <Tooltip title={u.message || u.error || ""}>
        <Tag color={meta.color}>{meta.label}</Tag>
      </Tooltip>
    )
  }},
  ]

  const groupColumns = [
    { title: "组名", dataIndex: "name", key: "name", render: (v: string, r: HostGroup) => (
      <Space><Text strong>{v}</Text>{r.origin === "legacy" && <Tag color="orange">未纳管</Tag>}</Space>
    )},
    { title: "说明", dataIndex: "description", key: "description", render: (v: string | null) => v || "-" },
    { title: "主机数", dataIndex: "member_count", key: "member_count", width: 90, render: (v: number) => <Tag color="blue">{v}</Tag> },
    { title: "操作", key: "action", width: 90, render: (_: unknown, r: HostGroup) => (
      <Popconfirm title="确定删除该组?" description="若组内仍有主机会拒绝删除" onConfirm={() => handleDeleteGroup(r.name)}>
        <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
      </Popconfirm>
    )},
  ]

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ReloadOutlined />} onClick={fetchHosts} loading={loading}>刷新</Button>
        <Select
          allowClear
          placeholder="按组筛选主机"
          style={{ width: 180 }}
          value={groupFilter}
          options={groupOptions}
          onChange={(v) => setGroupFilter(v)}
        />
        <Input.Search
          allowClear
          placeholder="搜索 主机名/IP/AgentID/OS"
          value={hostSearch}
          onChange={(e) => setHostSearch(e.target.value)}
          style={{ width: 240 }}
        />
        <Tooltip title="勾选后会显示 status=已下线 的软删除主机，方便做物理删除">
          <Switch
            checked={showDecommissioned}
            onChange={setShowDecommissioned}
            checkedChildren="含已下线"
            unCheckedChildren="含已下线"
          />
        </Tooltip>
        <Button icon={<TeamOutlined />} onClick={() => setGroupModalOpen(true)}>主机组管理</Button>
      </Space>

      <Card title="纳管令牌" id="token-form" style={{ marginBottom: 24 }}>
        <Form layout="inline" onFinish={handleCreateToken} initialValues={{ ttl_hours: 24, uses: 1 }}>
          <Form.Item name="group" label="组">
            <Select style={{ width: 160 }} allowClear placeholder="默认(未分组)" options={groupOptions} />
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

      <Card title="主机组" style={{ marginBottom: 24 }}>
        <Table
          dataSource={groups}
          columns={groupColumns}
          rowKey="name"
          pagination={false}
          size="small"
          locale={{ emptyText: <Empty description="暂无主机组" /> }}
        />
      </Card>

      <Card title={`主机列表 (${hosts.length})`}>
        <Table
          dataSource={filteredHosts}
          columns={columns}
          rowKey="agent_id"
          loading={loading}
          pagination={{ pageSize: 20 }}
          rowClassName={(r: Host) => r.status === "decommissioned" ? "host-row-decommissioned" : ""}
          locale={{
            emptyText: showDecommissioned ? (
              <div style={{ padding: 40 }}>
                <CloudServerOutlined style={{ fontSize: 48, color: "#ccc" }} />
                <div style={{ marginTop: 16, color: "#999" }}>暂无纳管主机（包括已下线）</div>
              </div>
            ) : (
              <div style={{ padding: 40 }}>
                <CloudServerOutlined style={{ fontSize: 48, color: "#ccc" }} />
                <div style={{ marginTop: 16, color: "#999" }}>暂无纳管主机</div>
                <div style={{ marginTop: 8, color: "#999", fontSize: 12 }}>
                  勾选右上角『含已下线』可查看已下线主机
                </div>
              </div>
            ),
          }}
        />
      </Card>

      <Modal title="新建主机组" open={groupModalOpen} onOk={handleCreateGroup} onCancel={() => { setGroupModalOpen(false); groupForm.resetFields() }} okText="创建" cancelText="取消">
        <Form form={groupForm} layout="vertical">
          <Form.Item name="name" label="组名" rules={[{ required: true, message: "请输入组名" }, { max: 128, message: "组名不超过 128 字符" }]}>
            <Input placeholder="例如：生产环境、核心区" />
          </Form.Item>
          <Form.Item name="description" label="说明">
            <Input.TextArea rows={2} placeholder="可选" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
