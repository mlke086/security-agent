import { useEffect, useState } from "react"
import { formatBeijing } from "../utils/time"
import { Button, Card, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Tooltip, message } from "antd"
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined, UndoOutlined } from "@ant-design/icons"
import { createUser, deleteUser, listUsers, restoreUser, updateUser, type ManagedUser, type UserRole } from "../api/client"
import { useAuth } from "../context/AuthContext"

const roleOptions = [
  { value: "admin", label: "管理员" },
  { value: "analyst", label: "分析员" },
  { value: "responder", label: "响应员" },
  { value: "viewer", label: "观察者" },
]

const roleLabels: Record<UserRole, string> = { admin: "管理员", analyst: "分析员", responder: "响应员", viewer: "观察者" }

// V10 4.5 (2026-07-30): shared error helper. The same
// ``error?.response?.data?.detail || fallback`` pattern appeared
// three times in this file (and a near-identical one in many
// other pages -- the goal here is to centralise the message
// shape so a future backend change (e.g. returning a structured
// ``{code, message, hint}`` body) is a one-line update.
function showError(err: unknown, fallback: string): void {
  const anyErr = err as { response?: { data?: { detail?: unknown } } } | null | undefined
  const detail = anyErr?.response?.data?.detail
  const text = typeof detail === "string" && detail ? detail : fallback
  message.error(text)
}

export default function UsersPage() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [loading, setLoading] = useState(false)
  const [includeDeleted, setIncludeDeleted] = useState(false)
  const [editing, setEditing] = useState<ManagedUser | null>(null)
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm()

  const load = async () => {
    setLoading(true)
    try { setUsers((await listUsers(includeDeleted)).items) }
    catch { message.error("加载用户列表失败") }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [includeDeleted])

  const showCreate = () => { setEditing(null); form.resetFields(); form.setFieldsValue({ role: "viewer" }); setOpen(true) }
  const showEdit = (record: ManagedUser) => { setEditing(record); form.setFieldsValue({ username: record.username, role: record.role, disabled: record.disabled }); setOpen(true) }
  const submit = async () => {
    try {
      const values = await form.validateFields()
      if (editing) await updateUser(editing.username, values)
      else await createUser(values)
      message.success(editing ? "用户已更新" : "用户已创建")
      setOpen(false); await load()
    } catch (error: any) {
      if (!error?.errorFields) showError(error, "保存失败")
    }
  }
  const remove = async (username: string) => {
    try { await deleteUser(username); message.success("用户已删除，可在“显示已删除”中恢复"); await load() }
    catch (error: any) { showError(error, "删除失败") }
  }
  const restore = async (username: string) => {
    try { await restoreUser(username); message.success("用户已恢复"); await load() }
    catch (error: any) { showError(error, "恢复失败") }
  }
  const formatTime = (value: string | null) => value ? formatBeijing(value) : "-"

  return <Card title="用户管理" extra={<Space>
    <Tooltip title="包含可恢复的软删除账号"><Switch checked={includeDeleted} onChange={setIncludeDeleted} checkedChildren="显示已删除" unCheckedChildren="显示已删除" /></Tooltip>
    <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>刷新</Button>
    <Button type="primary" icon={<PlusOutlined />} onClick={showCreate}>新增用户</Button>
  </Space>}>
    <Table rowKey="username" loading={loading} dataSource={users} pagination={{ pageSize: 20 }} columns={[
      { title: "用户名", dataIndex: "username" },
      { title: "角色", dataIndex: "role", width: 120, render: (v: UserRole) => <Tag color={v === "admin" ? "red" : v === "analyst" ? "blue" : v === "responder" ? "orange" : "default"}>{roleLabels[v]}</Tag> },
      { title: "状态", width: 110, render: (_: unknown, r: ManagedUser) => r.deleted_at ? <Tag>已删除</Tag> : r.disabled ? <Tag color="warning">已停用</Tag> : <Tag color="success">启用</Tag> },
      { title: "创建时间", dataIndex: "created_at", render: formatTime },
      { title: "最近登录", dataIndex: "last_login_at", render: formatTime },
      { title: "操作", width: 190, render: (_: unknown, r: ManagedUser) => r.deleted_at
        ? <Button size="small" icon={<UndoOutlined />} onClick={() => restore(r.username)}>恢复</Button>
        : <Space><Button size="small" icon={<EditOutlined />} onClick={() => showEdit(r)}>编辑</Button><Popconfirm title="删除此用户？" description="账号将无法登录，之后可恢复。" onConfirm={() => remove(r.username)} disabled={r.username === me?.username}><Button size="small" danger icon={<DeleteOutlined />} disabled={r.username === me?.username}>删除</Button></Popconfirm></Space> },
    ]} />
    <Modal title={editing ? "编辑用户" : "新增用户"} open={open} onOk={submit} onCancel={() => setOpen(false)} okText="保存" cancelText="取消" destroyOnClose>
      <Form form={form} layout="vertical">
        <Form.Item name="username" label="用户名" rules={[{ required: true }, { pattern: /^[A-Za-z0-9_]{3,32}$/, message: "请输入 3-32 位字母、数字或下划线" }]}><Input disabled={editing?.username === me?.username} autoComplete="off" /></Form.Item>
        {!editing && <Form.Item name="password" label="初始密码" rules={[{ required: true }, { min: 12, message: "密码至少 12 位" }]}><Input.Password autoComplete="new-password" /></Form.Item>}
        <Form.Item name="role" label="角色" rules={[{ required: true }]}><Select options={roleOptions} disabled={editing?.username === me?.username} /></Form.Item>
        {editing && <Form.Item name="disabled" label="账号状态" valuePropName="checked"><Switch checkedChildren="停用" unCheckedChildren="启用" disabled={editing.username === me?.username} /></Form.Item>}
      </Form>
    </Modal>
  </Card>
}