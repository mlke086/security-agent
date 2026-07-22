import { useEffect, useState } from "react"
import { Select, Radio, Space, Tag } from "antd"
import { listHosts, listGroups, type Host, type HostGroup } from "../api/client"

export interface TargetSelectorProps {
  value?: string[]
  onChange?: (value: string[]) => void
}

/**
 * 扫描目标选择器。支持两种模式：
 *   - 按主机：多选已纳管主机（agent_id），按组折叠便于定位，显示 hostname/ip
 *   - 按组：多选主机组，后端 _resolve_targets 会自动展开为该组全部在线主机
 *
 * 两种模式的选择会合并成 targets: string[]（agent_id + 组名）。
 * 后端已支持组名展开，前端无需额外处理。
 */
export default function TargetSelector({ value = [], onChange }: TargetSelectorProps) {
  const [mode, setMode] = useState<"host" | "group">("host")
  const [hosts, setHosts] = useState<Host[]>([])
  const [groups, setGroups] = useState<HostGroup[]>([])
  const [selectedHosts, setSelectedHosts] = useState<string[]>([])
  const [selectedGroups, setSelectedGroups] = useState<string[]>([])

  useEffect(() => {
    let alive = true
    Promise.all([
      listHosts({ status: "online" }).catch(() => ({ items: [] as Host[] })),
      listGroups().catch(() => ({ items: [] as HostGroup[] })),
    ]).then(([h, g]) => {
      if (!alive) return
      setHosts(h.items || [])
      setGroups(g.items || [])
    })
    return () => { alive = false }
  }, [])

  // 初始化：根据已有 value 推断选中项（编辑/回显场景）
  useEffect(() => {
    if (!value || value.length === 0) return
    const groupNames = new Set(groups.map((g) => g.name))
    const hostIds = new Set(hosts.map((h) => h.agent_id))
    const asGroups = value.filter((v) => groupNames.has(v))
    const asHosts = value.filter((v) => hostIds.has(v))
    if (asGroups.length > 0 && asHosts.length === 0) setMode("group")
    setSelectedGroups(asGroups)
    setSelectedHosts(asHosts)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hosts, groups])

  const emit = (hostsSel: string[], groupsSel: string[]) => {
    onChange?.([...hostsSel, ...groupsSel])
  }

  const handleModeChange = (newMode: "host" | "group") => {
    // P3-8 修复：切换模式时清空另一模式的选择，避免旧选择残留合并进 targets
    // （原先切换后 selectedHosts/selectedGroups 都保留，摘要却只渲染当前模式）。
    setMode(newMode)
    if (newMode === "host") {
      setSelectedGroups([])
      emit(selectedHosts, [])
    } else {
      setSelectedHosts([])
      emit([], selectedGroups)
    }
  }

  const handleHostChange = (v: string[]) => {
    setSelectedHosts(v)
    emit(v, selectedGroups)
  }

  const handleGroupChange = (v: string[]) => {
    setSelectedGroups(v)
    emit(selectedHosts, v)
  }

  const hostOptions = hosts.map((h) => ({
    label: `${h.hostname || h.agent_id} (${h.ip || "-"})${h.group ? ` · ${h.group}` : ""}`,
    value: h.agent_id,
  }))

  const groupOptions = groups.map((g) => ({
    label: `${g.name} (${g.member_count} 台)`,
    value: g.name,
  }))

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Radio.Group value={mode} onChange={(e) => handleModeChange(e.target.value)} optionType="button" buttonStyle="solid" size="small">
        <Radio.Button value="host">按主机</Radio.Button>
        <Radio.Button value="group">按组</Radio.Button>
      </Radio.Group>

      {mode === "host" ? (
        <Select
          mode="multiple"
          showSearch
          placeholder={hosts.length === 0 ? "暂无在线主机" : "选择目标主机（可多选）"}
          style={{ width: "100%" }}
          value={selectedHosts}
          options={hostOptions}
          onChange={handleHostChange}
          filterOption={(input, option) =>
            (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
          }
          notFoundContent="暂无在线主机，请先在主机纳管页纳管并确保主机在线"
        />
      ) : (
        <Select
          mode="multiple"
          placeholder={groups.length === 0 ? "暂无主机组" : "选择主机组（可多选，将扫描组内全部在线主机）"}
          style={{ width: "100%" }}
          value={selectedGroups}
          options={groupOptions}
          onChange={handleGroupChange}
          notFoundContent="暂无主机组，请先在主机纳管页创建组并纳管主机"
        />
      )}

      {(selectedHosts.length > 0 || selectedGroups.length > 0) && (
        <div>
          <span style={{ color: "#999", fontSize: 12, marginRight: 8 }}>已选目标：</span>
          {selectedHosts.map((id) => <Tag color="blue" key={id}>{id}</Tag>)}
          {selectedGroups.map((g) => <Tag color="purple" key={g}>{g}(组)</Tag>)}
        </div>
      )}
    </Space>
  )
}
