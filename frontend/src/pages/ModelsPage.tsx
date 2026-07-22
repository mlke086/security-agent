import { useEffect, useState } from "react"
import { Card, Table, Tag, Button, Space, message, Modal, Form, Input, InputNumber, Select, Switch, Popconfirm, Tooltip } from "antd"
import { PlusOutlined, ReloadOutlined, ThunderboltOutlined, StarOutlined, EditOutlined, DeleteOutlined } from "@ant-design/icons"
import {
  listModels, createModel, updateModel, deleteModel, setDefaultModel, testModel,
  type LlmModel, type ModelSubmit,
} from "../api/client"

// 需求4：4 家预置在线 API 模型（均为 OpenAI 兼容协议），key 由用户提供/编辑。
const PRESETS: Record<string, { label: string; provider: string; model_name: string; base_url: string }> = {
  volcengine: { label: "火山方舟", provider: "openai", model_name: "glm-5.2", base_url: "https://ark.cn-beijing.volces.com/api/v3" },
  kimi: { label: "Kimi (月之暗面)", provider: "openai", model_name: "kimi-k3", base_url: "https://api.moonshot.cn/v1" },
  deepseek: { label: "DeepSeek", provider: "openai", model_name: "deepseek-v4-pro", base_url: "https://api.deepseek.com/v1" },
  minimax: { label: "MiniMax", provider: "openai", model_name: "MiniMax-M3", base_url: "https://api.minimaxi.com/v1" },
}

const PROVIDER_LABEL: Record<string, string> = { openai: "OpenAI 兼容", claude: "Claude", vllm: "vLLM" }

export default function ModelsPage() {
  const [models, setModels] = useState<LlmModel[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<LlmModel | null>(null)
  const [testingId, setTestingId] = useState<number | null>(null)
  const [form] = Form.useForm()

  const fetchModels = async () => {
    setLoading(true)
    try {
      const res = await listModels()
      setModels(res.items || [])
    } catch { message.error("加载模型列表失败") }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchModels() }, [])

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    form.setFieldsValue({ provider: "openai", temperature: 0.1, max_tokens: 4096, supports_structured: true, enabled: true, is_default: false })
    setModalOpen(true)
  }

  const openEdit = (m: LlmModel) => {
    setEditing(m)
    form.setFieldsValue(m)
    setModalOpen(true)
  }

  const handlePreset = (key: string) => {
    const p = PRESETS[key]
    form.setFieldsValue({
      name: p.label,
      provider: p.provider,
      model_name: p.model_name,
      base_url: p.base_url,
      temperature: 0.1,
      max_tokens: 4096,
      supports_structured: true,
      enabled: true,
      is_default: false,
      api_key: form.getFieldValue("api_key") || "",
    })
    message.info(`已填充 ${p.label} 预置配置，请填写 API Key`)
  }

  const handleSubmit = async () => {
    try {
      const v = await form.validateFields()
      if (editing) {
        // 编辑时不强制改 key：留空则不更新
        const payload: ModelSubmit = { ...v }
        if (!v.api_key) delete payload.api_key
        await updateModel(editing.id, payload)
        message.success("模型已更新")
      } else {
        await createModel(v)
        message.success("模型已创建")
      }
      setModalOpen(false)
      fetchModels()
    } catch (e: any) {
      if (e?.errorFields) return
      message.error("保存失败")
    }
  }

  const handleDelete = async (id: number) => {
    try { await deleteModel(id); message.success("已删除"); fetchModels() }
    catch { message.error("删除失败") }
  }

  const handleSetDefault = async (id: number) => {
    try { await setDefaultModel(id); message.success("已设为默认"); fetchModels() }
    catch { message.error("设置失败") }
  }

  const handleTest = async (id: number) => {
    setTestingId(id)
    try {
      const res = await testModel(id)
      if (res.ok) message.success("连通正常：" + (res.reply || "").slice(0, 60))
      else message.error("连通失败：" + (res.error || "未知错误"))
    } catch { message.error("测试失败") }
    finally { setTestingId(null) }
  }

  const columns = [
    { title: "名称", dataIndex: "name", key: "name", render: (v: string, r: LlmModel) => (
      <Space>
        <span>{v}</span>
        {r.is_default && <Tag color="gold" icon={<StarOutlined />}>默认</Tag>}
        {!r.enabled && <Tag color="default">已禁用</Tag>}
      </Space>
    )},
    { title: "Provider", dataIndex: "provider", key: "provider", width: 120,
      render: (v: string) => <Tag color="blue">{PROVIDER_LABEL[v] || v}</Tag> },
    { title: "模型", dataIndex: "model_name", key: "model_name", width: 160 },
    { title: "Base URL", dataIndex: "base_url", key: "base_url", ellipsis: true,
      render: (v: string) => <Tooltip title={v}><span style={{ color: "#555" }}>{v || "-"}</span></Tooltip> },
    { title: "温度", dataIndex: "temperature", key: "temperature", width: 70 },
    { title: "Max Tokens", dataIndex: "max_tokens", key: "max_tokens", width: 100 },
    { title: "结构化输出", dataIndex: "supports_structured", key: "supports_structured", width: 100,
      render: (v: boolean) => v ? <Tag color="green">支持</Tag> : <Tag>不支持</Tag> },
    { title: "操作", key: "action", width: 280, render: (_: unknown, r: LlmModel) => (
      // F7 (2026-07-21): render 设默认 even on the default row, just
      // disabled -- otherwise the button group shrinks from 4 to 3 and
      // 删除 drifts to the right edge of the cell.
      <Space size="small">
        <Button size="small" icon={<ThunderboltOutlined />} loading={testingId === r.id} onClick={() => handleTest(r.id)}>测试</Button>
        <Button
          size="small"
          type="link"
          disabled={r.is_default}
          title={r.is_default ? "当前模型已是默认" : "设为默认模型"}
          onClick={() => handleSetDefault(r.id)}
        >
          设默认
        </Button>
        <Button size="small" type="link" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
        <Popconfirm title="确定删除该模型?" onConfirm={() => handleDelete(r.id)}>
          <Button size="small" type="link" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      </Space>
    )},
  ]

  return (
    <Card title="模型管理" extra={
      <Space>
        <Button icon={<ReloadOutlined />} onClick={fetchModels} loading={loading}>刷新</Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增模型</Button>
      </Space>
    }>
      <Card size="small" style={{ marginBottom: 16, background: "#f0f5ff" }}>
        <Space wrap>
          <span style={{ color: "#666" }}>快速填充预置配置：</span>
          {Object.entries(PRESETS).map(([k, p]) => (
            <Button key={k} size="small" onClick={() => { openCreate(); setTimeout(() => handlePreset(k), 50) }}>{p.label}</Button>
          ))}
        </Space>
      </Card>

      <Table
        dataSource={models}
        columns={columns}
        rowKey="id"
        loading={loading}
        pagination={false}
        locale={{ emptyText: "暂无模型，点击「新增模型」或使用预置配置快速添加" }}
      />

      <Modal
        title={editing ? "编辑模型" : "新增模型"}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
        width={560}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true, message: "请输入名称" }]}>
            <Input placeholder="例如：DeepSeek 生产" />
          </Form.Item>
          <Form.Item name="provider" label="Provider" rules={[{ required: true }]}>
            <Select options={[
              { label: "OpenAI 兼容 (火山/Kimi/DeepSeek/MiniMax/OpenAI/vLLM)", value: "openai" },
              { label: "Claude (Anthropic)", value: "claude" },
              { label: "vLLM (本地私有化)", value: "vllm" },
            ]} />
          </Form.Item>
          <Form.Item name="model_name" label="模型名" rules={[{ required: true, message: "请输入模型名" }]}>
            <Input placeholder="例如：glm-5.2、deepseek-v4-pro" />
          </Form.Item>
          <Form.Item name="base_url" label="Base URL" tooltip="OpenAI 兼容协议的 API 地址；Claude 留空">
            <Input placeholder="https://api.deepseek.com/v1" />
          </Form.Item>
          <Form.Item name="api_key" label="API Key" rules={editing ? [] : [{ required: true, message: "请输入 API Key" }]}
            extra={editing && editing.has_key ? "已配置，留空则保持不变" : undefined}
          >
            <Input.Password placeholder={editing ? (editing.has_key ? "留空则不修改" : "尚未配置，请输入") : "sk-..."} />
          </Form.Item>
          <Space style={{ width: "100%" }}>
            <Form.Item name="temperature" label="温度" style={{ width: 120 }}>
              <InputNumber min={0} max={2} step={0.1} style={{ width: "100%" }} />
            </Form.Item>
            <Form.Item name="max_tokens" label="Max Tokens" style={{ width: 140 }}>
              <InputNumber min={1} max={200000} style={{ width: "100%" }} />
            </Form.Item>
          </Space>
          <Space>
            <Form.Item name="supports_structured" label="支持结构化输出" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="enabled" label="启用" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="is_default" label="设为默认" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </Card>
  )
}
