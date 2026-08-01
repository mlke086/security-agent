import { useEffect, useState } from "react"
import { Drawer, Descriptions, Tag, Space, Skeleton, Empty, Button, Select, message } from "antd"
import { ReloadOutlined } from "@ant-design/icons"
import { getVuln, patchVulnStatus, type VulnFinding } from "../api/client"
import { formatBeijing, formatBeijingFull } from "../utils/time"
import AiEvidenceBadge from "./AiEvidenceBadge"

const SEV_COLORS: Record<string, string> = {
  critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue",
}
const SEV_LABEL: Record<string, string> = {
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示",
}

interface Props {
  findingId: string | null
  onClose: () => void
  onUpdated?: () => void
}

type VulnWithHost = VulnFinding & {
  host?: {
    agent_id: string
    hostname: string
    ip: string
    os: string
    arch: string
    kernel: string
    status: string
    agent_version?: string
    rule_version?: string
    last_heartbeat?: string
    group?: string | null
    owner?: string | null
    env?: string | null
  }
}

export default function VulnDetailDrawer({ findingId, onClose, onUpdated }: Props) {
  const [vuln, setVuln] = useState<VulnWithHost | null>(null)
  const [loading, setLoading] = useState(false)
  const [updating, setUpdating] = useState(false)

  useEffect(() => {
    if (!findingId) { setVuln(null); return }
    let alive = true
    setLoading(true)
    getVuln(findingId)
      .then((v) => { if (alive) setVuln(v as VulnWithHost) })
      .catch(() => { if (alive) message.error("加载漏洞详情失败") })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [findingId])

  const onChangeStatus = async (newStatus: VulnFinding["status"]) => {
    if (!vuln) return
    setUpdating(true)
    try {
      await patchVulnStatus(vuln.finding_id, newStatus)
      message.success("状态已更新")
      const v = await getVuln(vuln.finding_id)
      setVuln(v as VulnWithHost)
      onUpdated?.()
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "更新失败")
    } finally { setUpdating(false) }
  }

  const open = !!findingId

  return (
    <Drawer
      title={vuln ? `漏洞详情 · ${vuln.name}` : "漏洞详情"}
      open={open}
      onClose={onClose}
      width={560}
      extra={
        <Button icon={<ReloadOutlined />} size="small" loading={loading}
          onClick={() => findingId && getVuln(findingId).then((v) => setVuln(v as VulnWithHost)).catch(() => message.error("刷新失败"))}>
          刷新
        </Button>
      }
    >
      {loading && !vuln ? (<Skeleton active />)
        : !vuln ? (<Empty description="未找到该漏洞" />)
        : (
        <Space direction="vertical" size="large" style={{ width: "100%" }}>
          {vuln.host && (
            <div>
              <div style={{ fontWeight: 500, marginBottom: 6 }}>主机信息</div>
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="主机名">{vuln.host.hostname || "-"}</Descriptions.Item>
                <Descriptions.Item label="IP">{vuln.host.ip || "-"}</Descriptions.Item>
                <Descriptions.Item label="OS / 内核">{vuln.host.os || "-"} / {vuln.host.kernel || "-"}</Descriptions.Item>
                <Descriptions.Item label="业务分组">
                  {vuln.host.group ? <Tag color="geekblue">{vuln.host.group}</Tag> : <span style={{ color: "#bbb" }}>未分组</span>}
                </Descriptions.Item>
                <Descriptions.Item label="Owner">
                  {vuln.host.owner || <span style={{ color: "#bbb" }}>未指定</span>}
                </Descriptions.Item>
                <Descriptions.Item label="环境">
                  {vuln.host.env ? <Tag>{vuln.host.env}</Tag> : <span style={{ color: "#bbb" }}>未指定</span>}
                </Descriptions.Item>
                <Descriptions.Item label="Agent 状态">
                  <Tag color={vuln.host.status === "online" ? "green" : vuln.host.status === "decommissioned" ? "default" : "red"}>
                    {vuln.host.status === "online" ? "在线" : vuln.host.status === "offline" ? "离线" : vuln.host.status === "decommissioned" ? "已下线" : (vuln.host.status || "-")}
                  </Tag>
                  <span style={{ marginLeft: 8, color: "#999", fontSize: 12 }}>
                    Agent {vuln.host.agent_version || "-"} / 规则 {vuln.host.rule_version || "-"}
                  </span>
                </Descriptions.Item>
                {vuln.host.last_heartbeat && (
                  <Descriptions.Item label="最后心跳">{formatBeijing(vuln.host.last_heartbeat)}</Descriptions.Item>
                )}
              </Descriptions>
            </div>
          )}

          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="主机">{vuln.hostname}</Descriptions.Item>
            <Descriptions.Item label="CVE">{vuln.cve || <Tag>基线检查</Tag>}</Descriptions.Item>
            <Descriptions.Item label="名称">{vuln.name}</Descriptions.Item>
            <Descriptions.Item label="分类"><Tag>{vuln.category}</Tag></Descriptions.Item>
            <Descriptions.Item label="严重等级">
              <Tag color={SEV_COLORS[vuln.severity] || "default"}>
                {SEV_LABEL[vuln.severity] || vuln.severity}
              </Tag>
              {vuln.ai_severity && vuln.ai_severity !== vuln.severity && (
                <Tag color={SEV_COLORS[vuln.ai_severity] || "default"} style={{ marginLeft: 6 }}>
                  AI 改判: {SEV_LABEL[vuln.ai_severity] || vuln.ai_severity}
                </Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <Select size="small" value={vuln.status} style={{ width: 120 }} loading={updating}
                onChange={onChangeStatus}
                options={[
                  { value: "open", label: <span>待修复</span> },
                  { value: "fixed", label: <span>已修复</span> },
                  { value: "accepted", label: <span>已接受</span> },
                ]} />
            </Descriptions.Item>
            <Descriptions.Item label="发现时间">{formatBeijing(vuln.detected_at)}</Descriptions.Item>
            {(vuln.scan_history ?? []).length > 0 && (
              <Descriptions.Item label="历史扫描时间">
                {(vuln.scan_history ?? []).map((t, i) => (
                  <div key={i} style={{ lineHeight: "20px" }}>
                    {formatBeijing(t)}
                  </div>
                ))}
              </Descriptions.Item>
            )}
            {vuln.first_fixed_at && (
              <Descriptions.Item label="首次修复">{formatBeijing(vuln.first_fixed_at)}</Descriptions.Item>
            )}
            {vuln.last_fixed_at && (
              <Descriptions.Item label="最近修复">{formatBeijing(vuln.last_fixed_at)}</Descriptions.Item>
            )}
            {vuln.ai_processed_at && (
              <Descriptions.Item label="AI 处理时间">{formatBeijingFull(vuln.ai_processed_at)}</Descriptions.Item>
            )}
          </Descriptions>

          <div>
            <div style={{ fontWeight: 500, marginBottom: 6 }}>AI 处理证据</div>
            <AiEvidenceBadge aiProcessed={vuln.ai_processed} aiReason={vuln.ai_reason} />
            {vuln.ai_reason && (
              <div style={{ color: "#666", fontSize: 12, marginTop: 4 }}>{vuln.ai_reason}</div>
            )}
            {vuln.ai_filtered && (
              <div style={{ marginTop: 6 }}><Tag color="default">AI 判定为误报</Tag></div>
            )}
          </div>

          <div>
            <div style={{ fontWeight: 500, marginBottom: 6 }}>证据</div>
            <div style={{ background: "#fafafa", padding: 10, borderRadius: 4, whiteSpace: "pre-wrap", fontSize: 12, maxHeight: 200, overflow: "auto" }}>
              {vuln.evidence || "(none)"}
            </div>
          </div>

          <div>
            <div style={{ fontWeight: 500, marginBottom: 6 }}>修复建议</div>
            {vuln.ai_fix_summary ? (
              <div>
                <div style={{ color: "#666", fontSize: 13, marginBottom: 4 }}>AI 核心建议:</div>
                <div style={{ background: "#f6ffed", padding: 10, borderRadius: 4, marginBottom: 6 }}>
                  {vuln.ai_fix_summary}
                </div>
              </div>
            ) : null}
            {vuln.fix_advice && (
              <div style={{ background: "#e6f4ff", padding: 10, borderRadius: 4, whiteSpace: "pre-wrap", fontSize: 13 }}>
                {vuln.fix_advice}
              </div>
            )}
            {!vuln.fix_advice && !vuln.ai_fix_summary && (
              <div style={{ color: "#999" }}>暂无修复建议</div>
            )}
          </div>
        </Space>
      )}
    </Drawer>
  )
}
