import { Tag, Tooltip } from "antd"
import { RobotOutlined, ClockCircleOutlined } from "@ant-design/icons"

interface Props {
  /** True when the LLM actually produced a verdict for this row. */
  aiProcessed?: boolean | null
  /** Optional model name to show in the tooltip. */
  aiModel?: string | null
  /** Optional reason text; e.g. "LLM 不可用，已按原始等级保留" */
  aiReason?: string | null
  /** "block" (default) | "compact" */
  size?: "block" | "compact"
}

/**
 * AiEvidenceBadge
 * 2026-07-29 UX upgrade: a single shared component that surfaces whether
 * AI actually processed a finding / report. Two visual states:
 *   - "AI 已处理"   blue,   with model name
 *   - "等待补扫"    gray,   with reason on hover
 *
 * Keeps the language consistent across ScanReport / VulnList / ScanTask.
 */
export default function AiEvidenceBadge({ aiProcessed, aiModel, aiReason, size = "block" }: Props) {
  const isAi = !!aiProcessed
  const label = isAi ? "AI 已处理" : "等待补扫"
  const icon = isAi ? <RobotOutlined /> : <ClockCircleOutlined />
  const color = isAi ? "blue" : "default"
  const tooltipText = isAi
    ? `AI 模型: ${aiModel || "未知"}`
    : aiReason || "AI 未处理此记录，已按原始等级保留，等待补扫"

  if (size === "compact") {
    return (
      <Tooltip title={tooltipText}>
        <Tag color={color} style={{ marginRight: 0 }}>
          {icon} {label}
        </Tag>
      </Tooltip>
    )
  }
  return (
    <Tooltip title={tooltipText}>
      <Tag color={color} icon={icon} style={{ marginRight: 0 }}>
        {label}
        {isAi && aiModel ? ` · ${aiModel}` : ""}
      </Tag>
    </Tooltip>
  )
}
