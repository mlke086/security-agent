import { useEffect, useState } from "react"
import { Drawer, Button, Space, Tag, Descriptions, message, Spin, Typography } from "antd"
import { EditOutlined, SaveOutlined, CloseOutlined } from "@ant-design/icons"
import CodeMirror from "@uiw/react-codemirror"
import { yaml } from "@codemirror/lang-yaml"
import { githubLight } from "@uiw/codemirror-theme-github"
import { getNucleiTemplate, saveNucleiTemplate, type NucleiTemplateMeta } from "../api/client"

const SEV_COLOR: Record<string, string> = {
  critical: "red", high: "volcano", medium: "gold", low: "green", info: "blue",
}

interface Props {
  path: string | null
  onClose: () => void
}

/** Nuclei 模板详情/编辑抽屉：CodeMirror YAML 高亮 + 可切换编辑保存。 */
export default function NucleiTemplateViewer({ path, onClose }: Props) {
  const [meta, setMeta] = useState<NucleiTemplateMeta | null>(null)
  const [content, setContent] = useState("")
  const [loading, setLoading] = useState(false)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (!path) return
    let alive = true // S-P2-9 (V12): drop stale responses when path changes
    setLoading(true)
    setEditing(false)
    setDirty(false)
    getNucleiTemplate(path)
      .then((m) => {
        if (!alive) return
        setMeta(m)
        setContent(m.content || "")
      })
      .catch(() => {
        if (alive) message.error("加载模板失败")
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [path])

  const handleSave = async () => {
    if (!path) return
    setSaving(true)
    try {
      const r = await saveNucleiTemplate(path, content)
      message.success("已保存到本地（ES，不下发到 agent）")
      setEditing(false)
      setDirty(false)
      setMeta((prev) => (prev ? { ...prev, template_id: r.template_id, name: r.name, severity: r.severity } : prev))
    } catch {
      message.error("保存失败")
    } finally {
      setSaving(false)
    }
  }

  const cancelEdit = () => {
    setEditing(false)
    if (dirty && meta) setContent(meta.content || "")
    setDirty(false)
  }

  return (
    <Drawer
      title={path ? `模板详情` : ""}
      open={!!path}
      onClose={onClose}
      width={760}
      destroyOnClose
      extra={
        meta && (
          <Space>
            {editing ? (
              <>
                <Button icon={<SaveOutlined />} type="primary" loading={saving} onClick={handleSave} disabled={!dirty}>
                  保存
                </Button>
                <Button icon={<CloseOutlined />} onClick={cancelEdit}>取消</Button>
              </>
            ) : (
              <Button icon={<EditOutlined />} onClick={() => setEditing(true)}>编辑</Button>
            )}
          </Space>
        )
      }
    >
      {loading ? (
        <Spin style={{ display: "block", margin: "60px auto" }} />
      ) : meta ? (
        <>
          <Descriptions size="small" column={2} bordered style={{ marginBottom: 12 }}>
            <Descriptions.Item label="模板 ID" span={2}>
              <code>{meta.template_id || "-"}</code>
            </Descriptions.Item>
            <Descriptions.Item label="名称">{meta.name || "-"}</Descriptions.Item>
            <Descriptions.Item label="分类"><Tag color="blue">{meta.category}</Tag></Descriptions.Item>
            <Descriptions.Item label="严重等级">
              {meta.severity ? <Tag color={SEV_COLOR[meta.severity] || "default"}>{meta.severity}</Tag> : "-"}
            </Descriptions.Item>
            <Descriptions.Item label="作者">{meta.author || "-"}</Descriptions.Item>
            <Descriptions.Item label="路径" span={2}><Typography.Text code style={{ fontSize: 12 }}>{meta.path}</Typography.Text></Descriptions.Item>
            {meta.tags?.length > 0 && (
              <Descriptions.Item label="标签" span={2}>
                <Space size={4} wrap>{meta.tags.map((t) => <Tag key={t}>{t}</Tag>)}</Space>
              </Descriptions.Item>
            )}
          </Descriptions>
          <CodeMirror
            value={content}
            theme={githubLight}
            extensions={[yaml()]}
            editable={editing}
            basicSetup={{ lineNumbers: true, highlightActiveLine: editing, foldGutter: true }}
            onChange={(val) => {
              setContent(val)
              setDirty(true)
            }}
            style={{ border: "1px solid #eee", borderRadius: 6, fontSize: 13 }}
          />
          <div style={{ marginTop: 8, color: "#999", fontSize: 12 }}>
            编辑保存仅更新本地 ES 中的模板，不会下发到 agent。agent 模板仍走「同步 Nuclei 模板」整包下发。
          </div>
        </>
      ) : null}
    </Drawer>
  )
}
