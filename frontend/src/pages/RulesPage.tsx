import { useState } from "react"
import { Card, Button, Descriptions, Tag, message, Space, Spin } from "antd"
import { SyncOutlined, SafetyCertificateOutlined } from "@ant-design/icons"
import api from "../api/client"

export default function RulesPage() {
  const [syncing, setSyncing] = useState(false)
  const [version, setVersion] = useState("")
  const [count, setCount] = useState(0)
  const [loadingVer, setLoadingVer] = useState(false)

  const fetchVersion = async () => {
    setLoadingVer(true)
    try {
      const res = await api.get("/rules/version")
      setVersion(res.data.version)
    } catch { /* ignore */ }
    finally { setLoadingVer(false) }
  }

  useState(() => { fetchVersion() })  // eslint-disable-line

  const handleSync = async () => {
    setSyncing(true)
    try {
      const res = await api.post("/rules/sync", { source: "nvd" })
      setVersion(res.data.version)
      setCount(res.data.count)
      message.success("Rules synced: " + res.data.count + " rules (v" + res.data.version + ")")
    } catch { message.error("Sync failed - NVD API may be rate-limited, try again later") }
    finally { setSyncing(false) }
  }

  return (
    <div>
      <Card title="Rules Management" extra={
        <Space>
          <Button onClick={fetchVersion} loading={loadingVer}>Refresh</Button>
          <Button type="primary" icon={<SyncOutlined />} onClick={handleSync} loading={syncing}>
            Sync from NVD
          </Button>
        </Space>
      }>
        <Descriptions bordered column={2} size="small">
          <Descriptions.Item label="Current Version">
            {version ? <Tag color="blue">{version}</Tag> : <Spin size="small" />}
          </Descriptions.Item>
          <Descriptions.Item label="Last Sync Count">{count || "-"}</Descriptions.Item>
          <Descriptions.Item label="Data Source">
            <Tag color="green">NVD (National Vulnerability Database)</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Sync Schedule">Daily at 03:00 (cron)</Descriptions.Item>
          <Descriptions.Item label="Rule Categories" span={2}>
            <Tag color="red">sys_vuln</Tag> System vulnerabilities (CVE-based)
            <Tag color="blue" style={{ marginLeft: 8 }}>baseline</Tag> Security baseline checks (5 static rules)
          </Descriptions.Item>
          <Descriptions.Item label="Baseline Rules" span={2}>
            <div style={{ fontSize: 13 }}>
              <div><SafetyCertificateOutlined /> BL-001: SSH root login disabled</div>
              <div><SafetyCertificateOutlined /> BL-002: Password min length</div>
              <div><SafetyCertificateOutlined /> BL-003: Firewall active check</div>
              <div><SafetyCertificateOutlined /> BL-004: Audit logging enabled</div>
              <div><SafetyCertificateOutlined /> BL-005: Core dumps restricted</div>
            </div>
          </Descriptions.Item>
        </Descriptions>

        <Card size="small" title="Distribution" style={{ marginTop: 16, background: "#f0f5ff" }}>
          <p style={{ fontSize: 13, color: "#666", marginBottom: 4 }}>
            Agents automatically check rule version on each heartbeat. When an agent reports an outdated rule version,
            the server pushes a <Tag>rule_update</Tag> command with the new pack download URL and signature.
          </p>
          <p style={{ fontSize: 13, color: "#666" }}>
            Rule packs are HMAC-SHA256 signed. Agents verify the signature before applying the update (hot-reload, no restart required).
          </p>
        </Card>
      </Card>
    </div>
  )
}
