/**AlertInboxPage - EDR alert triage (Phase 2 of monitoring plan).

Layout:
  - Toolbar: severity + source + status filters, search by hostname,
    manual refresh, "Ingest test alert" button (admin only) for
    verifying the webhook end-to-end.
  - Table: alert_id, severity, source, title, host, rule, mitre,
    status, occurred, action (status update + view details).
  - Detail Drawer: full payload + IOCs + raw JSON for forensic review.

Reuses backend endpoints from /api/v1/alerts (Phase 1).
The list polls every 15s; status changes are visible to other
operators within one tick.
*/
import { useEffect, useMemo, useState, useCallback } from "react"
import { formatBeijing } from "../utils/time"
import { showError } from "../utils/showError"
import {
  Card, Table, Tag, Space, Button, Select, Input, Drawer, Descriptions,
  Row, Col, message, Tooltip, Empty, Statistic, Tabs, Typography,
} from "antd"
import {
  ReloadOutlined, SearchOutlined, AlertOutlined, EyeOutlined,
  ApiOutlined, CheckCircleOutlined, CloseCircleOutlined, LinkOutlined,
} from "@ant-design/icons"
import {
  listAlerts, getAlert, ingestAlert, updateAlertStatus,
  type AlertRecord, type AlertSeverity, type AlertStatus, type AlertSource,
} from "../api/alerts"

const { Text, Paragraph } = Typography

const SEVERITY_META: Record<string, { color: string; label: string }> = {
  critical: { color: "red",       label: "Critical" },
  high:     { color: "volcano",   label: "High" },
  medium:   { color: "gold",      label: "Medium" },
  low:      { color: "green",     label: "Low" },
  info:     { color: "blue",      label: "Info" },
}

const STATUS_META: Record<string, { color: string; label: string }> = {
  new:             { color: "red",     label: "New" },
  acknowledged:    { color: "gold",    label: "Acknowledged" },
  in_progress:     { color: "blue",    label: "In progress" },
  resolved:        { color: "green",   label: "Resolved" },
  false_positive:  { color: "default", label: "False positive" },
}

const SOURCE_META: Record<string, { color: string; label: string }> = {
  wazuh:        { color: "geekblue", label: "Wazuh" },
  elkeid:       { color: "purple",   label: "Elkeid" },
  syslog:       { color: "cyan",     label: "Syslog" },
  elastic:      { color: "magenta",  label: "Elastic" },
  crowdstrike:  { color: "volcano",  label: "CrowdStrike" },
  sentinelone:  { color: "orange",   label: "SentinelOne" },
  secagent:     { color: "blue",     label: "SecAgent" },
  unknown:      { color: "default",  label: "Unknown" },
}

function metaFor<T>(table: Record<string, T>, key: string | undefined, fallback: T): T {
  if (key && table[key]) return table[key]
  return fallback
}

interface Counts {
  total: number
  critical: number
  high: number
  unhandled: number
}

export default function AlertInboxPage() {
  const [items, setItems] = useState<AlertRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [counts, setCounts] = useState<Counts>({ total: 0, critical: 0, high: 0, unhandled: 0 })
  const [severity, setSeverity] = useState<AlertSeverity | undefined>(undefined)
  const [status, setStatus] = useState<AlertStatus | undefined>(undefined)
  const [source, setSource] = useState<AlertSource | undefined>(undefined)
  const [hostname, setHostname] = useState("")
  const [debouncedHostname, setDebouncedHostname] = useState("")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [drawerAlertId, setDrawerAlertId] = useState<string | null>(null)
  const [drawerAlert, setDrawerAlert] = useState<AlertRecord | null>(null)
  const [drawerLoading, setDrawerLoading] = useState(false)
  const [activeTab, setActiveTab] = useState("overview")

  // Debounce hostname filter (200ms) so we don't fire on every keystroke
  useEffect(() => {
    const t = setTimeout(() => setDebouncedHostname(hostname), 200)
    return () => clearTimeout(t)
  }, [hostname])

  const fetchList = useCallback(async () => {
    setLoading(true)
    try {
      const res = await listAlerts({
        severity,
        status,
        source,
        hostname: debouncedHostname || undefined,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      })
      setItems(res.items || [])
      // Quick severity histogram from the current page
      const c: Counts = { total: res.count, critical: 0, high: 0, unhandled: 0 }
      for (const a of res.items || []) {
        if (a.severity === "critical") c.critical += 1
        if (a.severity === "high") c.high += 1
        if (a.status === "new" || a.status === "acknowledged") c.unhandled += 1
      }
      setCounts(c)
    } catch (err) {
      showError(err, "加载告警失败")
    } finally {
      setLoading(false)
    }
  }, [severity, status, source, debouncedHostname, page, pageSize])

  useEffect(() => { void fetchList() }, [fetchList])

  // Auto-refresh every 15 seconds (without resetting pagination)
  useEffect(() => {
    const t = setInterval(() => { void fetchList() }, 15000)
    return () => clearInterval(t)
  }, [fetchList])

  // Drawer load on selection
  useEffect(() => {
    if (!drawerAlertId) { setDrawerAlert(null); return }
    let alive = true
    setDrawerLoading(true)
    getAlert(drawerAlertId)
      .then((a) => { if (alive) { setDrawerAlert(a); setActiveTab("overview") } })
      .catch((err) => { if (alive) showError(err, "加载告警失败") })
      .finally(() => { if (alive) setDrawerLoading(false) })
    return () => { alive = false }
  }, [drawerAlertId])

  const updateStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus)
      message.success(`alert ${alertId} -> ${newStatus}`)
      // Refresh list and drawer payload
      await fetchList()
      if (drawerAlertId === alertId) {
        setDrawerAlert((cur) => cur ? { ...cur, status: newStatus } : cur)
      }
    } catch (err) {
      showError(err, "状态更新失败")
    }
  }

  const onIngestTest = async () => {
    // Send a small synthetic Wazuh-shaped payload so the operator can
    // verify the end-to-end (webhook -> normalize -> store -> list).
    const sample = {
      id: "manual-test-" + Date.now(),
      timestamp: new Date().toISOString(),
      agent: { name: "manual-test-host", id: "manual-agent", ip: "10.0.0.99" },
      rule: { level: 12, id: "9999", description: "Manual test alert from AlertInboxPage", groups: ["test"] },
      data: { srcip: "203.0.113.99", sha256: "deadbeefcafe" },
    }
    try {
      const res = await ingestAlert("wazuh", sample)
      message.success(`test alert ingested as ${res.alert_id}`)
      await fetchList()
    } catch (err) {
      showError(err, "注入失败")
    }
  }

  const columns = useMemo(() => [
    {
      title: "Severity",
      dataIndex: "severity",
      width: 110,
      render: (s: string) => {
        const m = metaFor(SEVERITY_META, s, { color: "default", label: s || "?" })
        return <Tag color={m.color}>{m.label}</Tag>
      },
    },
    {
      title: "Source",
      dataIndex: "source",
      width: 110,
      render: (s: string) => {
        const m = metaFor(SOURCE_META, s, { color: "default", label: s || "?" })
        return <Tag color={m.color}>{m.label}</Tag>
      },
    },
    {
      title: "Title",
      dataIndex: "title",
      ellipsis: { showTitle: true },
      render: (_: unknown, r: AlertRecord) => (
        <a onClick={() => setDrawerAlertId(r.alert_id)} style={{ color: "inherit" }}>
          {r.title || <Text type="secondary">(no title)</Text>}
        </a>
      ),
    },
    {
      title: "Host",
      dataIndex: "hostname",
      width: 160,
      render: (_: string, r: AlertRecord) => (
        <Tooltip title={r.host_ip || ""}>
          <Space size={4}>
            <Text>{r.hostname || <Text type="secondary">—</Text>}</Text>
          </Space>
        </Tooltip>
      ),
    },
    {
      title: "Rule",
      dataIndex: "rule_id",
      width: 120,
      render: (_: string, r: AlertRecord) => (
        <Tooltip title={r.rule_name || ""}>
          <Text code style={{ fontSize: 12 }}>{r.rule_id || "—"}</Text>
        </Tooltip>
      ),
    },
    {
      title: "MITRE",
      dataIndex: "mitre_attack",
      width: 130,
      render: (m: string[] | undefined) => (
        <Space size={2} wrap>
          {(m || []).slice(0, 3).map((t) => (
            <Tag key={t} color="purple" style={{ fontSize: 11 }}>{t}</Tag>
          ))}
        </Space>
      ),
    },
    {
      title: "Status",
      dataIndex: "status",
      width: 130,
      render: (s: string, r: AlertRecord) => {
        return (
          <Select
            size="small"
            value={s || "new"}
            style={{ width: 110 }}
            onChange={(v) => updateStatus(r.alert_id, v as AlertStatus)}
            options={[
              { value: "new",             label: <Tag color="red">New</Tag> },
              { value: "acknowledged",    label: <Tag color="gold">Acked</Tag> },
              { value: "in_progress",     label: <Tag color="blue">In prog</Tag> },
              { value: "resolved",        label: <Tag color="green">Resolved</Tag> },
              { value: "false_positive",  label: <Tag>FP</Tag> },
            ]}
          />
        )
      },
    },
    {
      title: "Received",
      dataIndex: "received_at",
      width: 170,
      render: (s: string) => (
        <Tooltip title={s}>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {s ? formatBeijing(s) : "—"}
          </Text>
        </Tooltip>
      ),
    },
    {
      title: "Action",
      width: 80,
      render: (_: unknown, r: AlertRecord) => (
        <Button size="small" icon={<EyeOutlined />} onClick={() => setDrawerAlertId(r.alert_id)}>
          Detail
        </Button>
      ),
    },
  ], [drawerAlertId])

  return (
    <div>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}><Card size="small"><Statistic title="Total in view" value={counts.total} prefix={<AlertOutlined />} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title="Critical (this page)" valueStyle={{ color: "#cf1322" }} value={counts.critical} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title="High (this page)" valueStyle={{ color: "#d4380d" }} value={counts.high} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title="Unhandled (new + acked)" valueStyle={{ color: "#d4b106" }} value={counts.unhandled} /></Card></Col>
      </Row>

      <Card
        title="EDR Alerts"
        extra={
          <Space>
            <Input
              allowClear
              placeholder="hostname contains…"
              prefix={<SearchOutlined />}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              style={{ width: 220 }}
            />
            <Select
              allowClear
              placeholder="severity"
              value={severity}
              onChange={(v) => setSeverity(v as AlertSeverity | undefined)}
              style={{ width: 120 }}
              options={[
                { value: "critical", label: "Critical" },
                { value: "high",     label: "High" },
                { value: "medium",   label: "Medium" },
                { value: "low",      label: "Low" },
                { value: "info",     label: "Info" },
              ]}
            />
            <Select
              allowClear
              placeholder="source"
              value={source}
              onChange={(v) => setSource(v as AlertSource | undefined)}
              style={{ width: 130 }}
              options={[
                { value: "wazuh",       label: "Wazuh" },
                { value: "elkeid",      label: "Elkeid" },
                { value: "syslog",      label: "Syslog" },
                { value: "elastic",     label: "Elastic" },
                { value: "crowdstrike", label: "CrowdStrike" },
                { value: "sentinelone", label: "SentinelOne" },
                { value: "secagent",    label: "SecAgent" },
                { value: "unknown",     label: "Unknown" },
              ]}
            />
            <Select
              allowClear
              placeholder="status"
              value={status}
              onChange={(v) => setStatus(v as AlertStatus | undefined)}
              style={{ width: 130 }}
              options={[
                { value: "new",            label: "New" },
                { value: "acknowledged",   label: "Acknowledged" },
                { value: "in_progress",    label: "In progress" },
                { value: "resolved",       label: "Resolved" },
                { value: "false_positive", label: "False positive" },
              ]}
            />
            <Tooltip title="Re-fetch">
              <Button icon={<ReloadOutlined />} onClick={fetchList} />
            </Tooltip>
            <Button icon={<ApiOutlined />} onClick={onIngestTest}>
              Ingest test alert
            </Button>
          </Space>
        }
      >
        <Table<AlertRecord>
          rowKey="alert_id"
          dataSource={items}
          columns={columns as any}
          loading={loading}
          size="small"
          pagination={{
            current: page,
            pageSize,
            total: counts.total,
            showSizeChanger: true,
            pageSizeOptions: ["20", "50", "100"],
            onChange: (p, ps) => { setPage(p); setPageSize(ps) },
            showTotal: (t) => `${t} alerts`,
          }}
          locale={{ emptyText: <Empty description="no alerts in view" /> }}
        />
      </Card>

      <Drawer
        title={drawerAlert ? `${drawerAlert.alert_id} — ${drawerAlert.title}` : "Alert detail"}
        open={drawerAlertId !== null}
        onClose={() => setDrawerAlertId(null)}
        width={720}
        loading={drawerLoading}
        destroyOnClose
        extra={
          drawerAlert && (
            <Space>
              {drawerAlert.source_url && (
                <Button icon={<LinkOutlined />} onClick={() => window.open(drawerAlert.source_url, "_blank")}>
                  Open in source
                </Button>
              )}
              <Button
                type="primary"
                icon={<CheckCircleOutlined />}
                disabled={drawerAlert.status === "resolved"}
                onClick={() => updateStatus(drawerAlert.alert_id, "resolved")}
              >
                Mark resolved
              </Button>
              <Button
                danger
                icon={<CloseCircleOutlined />}
                disabled={drawerAlert.status === "false_positive"}
                onClick={() => updateStatus(drawerAlert.alert_id, "false_positive")}
              >
                False positive
              </Button>
            </Space>
          )
        }
      >
        {drawerAlert && (
          <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
            {
              key: "overview",
              label: "Overview",
              children: (
                <Descriptions column={2} size="small" bordered>
                  <Descriptions.Item label="Severity">
                    {(() => {
                      const m = metaFor(SEVERITY_META, drawerAlert.severity, { color: "default", label: drawerAlert.severity || "?" })
                      return <Tag color={m.color}>{m.label}</Tag>
                    })()}
                  </Descriptions.Item>
                  <Descriptions.Item label="Status">
                    {(() => {
                      const m = metaFor(STATUS_META, drawerAlert.status, { color: "default", label: drawerAlert.status || "?" })
                      return <Tag color={m.color}>{m.label}</Tag>
                    })()}
                  </Descriptions.Item>
                  <Descriptions.Item label="Source">
                    {(() => {
                      const m = metaFor(SOURCE_META, drawerAlert.source, { color: "default", label: drawerAlert.source || "?" })
                      return <Tag color={m.color}>{m.label}</Tag>
                    })()}
                  </Descriptions.Item>
                  <Descriptions.Item label="Rule">
                    <Text code>{drawerAlert.rule_id || "—"}</Text>
                    {drawerAlert.rule_name && <Text type="secondary"> · {drawerAlert.rule_name}</Text>}
                  </Descriptions.Item>
                  <Descriptions.Item label="Host">
                    {drawerAlert.hostname || "—"}
                    {drawerAlert.host_ip && <Text type="secondary"> ({drawerAlert.host_ip})</Text>}
                  </Descriptions.Item>
                  <Descriptions.Item label="Agent">{drawerAlert.agent_id || "—"}</Descriptions.Item>
                  <Descriptions.Item label="Occurred">{drawerAlert.occurred_at}</Descriptions.Item>
                  <Descriptions.Item label="Received">{drawerAlert.received_at}</Descriptions.Item>
                  <Descriptions.Item label="Category" span={2}>{drawerAlert.category || "—"}</Descriptions.Item>
                  {drawerAlert.description && (
                    <Descriptions.Item label="Description" span={2}>
                      <Paragraph style={{ marginBottom: 0 }}>{drawerAlert.description}</Paragraph>
                    </Descriptions.Item>
                  )}
                  {drawerAlert.mitre_attack && drawerAlert.mitre_attack.length > 0 && (
                    <Descriptions.Item label="MITRE ATT&CK" span={2}>
                      <Space size={4} wrap>
                        {drawerAlert.mitre_attack.map((t) => <Tag key={t} color="purple">{t}</Tag>)}
                      </Space>
                    </Descriptions.Item>
                  )}
                </Descriptions>
              ),
            },
            {
              key: "iocs",
              label: "IOCs",
              children: (
                <div>
                  {!drawerAlert.iocs ? <Empty description="no IOCs" /> : (
                    <Space direction="vertical" style={{ width: "100%" }} size="middle">
                      {(["ips", "domains", "hashes", "urls", "emails", "users"] as const).map((k) => {
                        const list = drawerAlert.iocs?.[k] || []
                        if (list.length === 0) return null
                        return (
                          <div key={k}>
                            <Text strong>{k.toUpperCase()}:</Text>
                            <div style={{ marginTop: 4 }}>
                              {list.map((v, i) => (
                                <Tag key={i} style={{ fontFamily: "monospace", marginBottom: 4 }}>{v}</Tag>
                              ))}
                            </div>
                          </div>
                        )
                      })}
                    </Space>
                  )}
                </div>
              ),
            },
            {
              key: "raw",
              label: "Raw payload",
              children: (
                <pre style={{
                  background: "var(--ant-color-fill-quaternary, #f5f5f5)",
                  padding: 12,
                  borderRadius: 6,
                  fontSize: 12,
                  maxHeight: 480,
                  overflow: "auto",
                }}>
                  {JSON.stringify(drawerAlert.raw || drawerAlert, null, 2)}
                </pre>
              ),
            },
          ]} />
        )}
      </Drawer>
    </div>
  )
}
