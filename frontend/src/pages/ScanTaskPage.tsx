import { useState } from "react"
import { Card, Tabs, Form, Input, Button, Select, message, Table, Tag } from "antd"
import { SendOutlined, ThunderboltOutlined } from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import api from "../api/client"

interface ScanTask { task_id: string; source: string; targets: string[]; status: string; created_at: string; stats: { total: number; done: number; failed: number } }

export default function ScanTaskPage() {
  const [text, setText] = useState("")
  const [parsing, setParsing] = useState(false)
  const [parsed, setParsed] = useState<any>(null)
  const [submitting, setSubmitting] = useState(false)
  const [tasks, setTasks] = useState<ScanTask[]>([])
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleParse = async () => {
    setParsing(true)
    try {
      const res = await api.post("/vulnscan/tasks/parse", { intent_text: text })
      setParsed(res.data)
    } catch { message.error("解析失败") }
    finally { setParsing(false) }
  }

  const handleSubmit = async (source: string, extra?: any) => {
    setSubmitting(true)
    try {
      const body: any = { source }
      if (source === "dialog") {
        body.intent_text = text
        if (parsed) {
          body.targets = parsed.targets
          body.modules = parsed.modules
        }
      } else {
        body.targets = extra?.targets || []
        body.modules = extra?.modules || ["sys_vuln", "baseline"]
      }
      const res = await api.post("/vulnscan/tasks", body)
      message.success("任务已创建")
      navigate(`/scan-monitor/${res.data.task_id}`)
    } catch { message.error("创建失败") }
    finally { setSubmitting(false) }
  }

  const fetchTasks = async () => {
    setLoading(true)
    try {
      const res = await api.get("/vulnscan/tasks")
      setTasks(res.data.items)
    } catch { message.error("加载失败") }
    finally { setLoading(false) }
  }

  const columns = [
    { title: "任务ID", dataIndex: "task_id", key: "task_id", ellipsis: true, width: 150 },
    { title: "源", dataIndex: "source", key: "source", width: 80, render: (v: string) => v === "dialog" ? "对话" : "手动" },
    { title: "目标数", key: "targets", width: 80, render: (_: any, r: ScanTask) => r.targets?.length || 0 },
    { title: "进度", key: "progress", width: 120, render: (_: any, r: ScanTask) => `${r.stats?.done || 0}/${r.stats?.total || 0}` },
    { title: "状态", dataIndex: "status", key: "status", width: 100, render: (v: string) => {
      const colors: any = { queued: "default", dispatching: "processing", scanning: "processing", analyzing: "processing", completed: "success", failed: "error" }
      return <Tag color={colors[v] || "default"}>{v}</Tag>
    }},
    { title: "创建时间", dataIndex: "created_at", key: "created_at", width: 180, render: (v: string) => v?.slice(0, 19) || "-" },
    { title: "操作", key: "action", width: 100, render: (_: any, r: ScanTask) => (
      <Button size="small" type="link" onClick={() => navigate(`/scan-monitor/${r.task_id}`)}>监控</Button>
    )},
  ]

  return (
    <div>
      <Tabs defaultActiveKey="dialog" items={[
        {
          key: "dialog", label: <span><SendOutlined /> 对话式</span>, children: (
            <Card>
              <Form layout="inline">
                <Form.Item style={{ flex: 1 }}>
                  <Input.TextArea rows={2} placeholder='例如：扫描生产 Linux 主机系统漏洞和安全基线' value={text} onChange={e => setText(e.target.value)} />
                </Form.Item>
                <Form.Item>
                  <Button icon={<ThunderboltOutlined />} onClick={handleParse} loading={parsing} type="primary">解析</Button>
                </Form.Item>
              </Form>
              {parsed && (
                <Card size="small" style={{ marginTop: 12, background: "#f0f5ff" }}>
                  <div>目标: {parsed.targets?.join(", ") || "未解析"}</div>
                  <div>模块: {parsed.modules?.join(", ") || "-"}</div>
                  <Button type="primary" style={{ marginTop: 8 }} onClick={() => handleSubmit("dialog")} loading={submitting}>确认并执行</Button>
                </Card>
              )}
            </Card>
          )
        },
        {
          key: "manual", label: <span><ThunderboltOutlined /> 手动</span>, children: (
            <Card>
              <Form onFinish={(v) => handleSubmit("manual", { targets: v.targets?.split(",").map((s: string) => s.trim()), modules: v.modules })} initialValues={{ modules: ["sys_vuln", "baseline"] }}>
                <Form.Item name="targets" label="目标主机" rules={[{ required: true }]}>
                  <Input placeholder="agent_id列表，逗号分隔" />
                </Form.Item>
                <Form.Item name="modules" label="扫描模块">
                  <Select mode="multiple" options={[{ label: "系统漏洞", value: "sys_vuln" }, { label: "安全基线", value: "baseline" }]} />
                </Form.Item>
                <Form.Item>
                  <Button type="primary" htmlType="submit" loading={submitting}>开始扫描</Button>
                </Form.Item>
              </Form>
            </Card>
          )
        },
        {
          key: "tasks", label: "任务列表", children: (
            <Table dataSource={tasks} columns={columns} rowKey="task_id" loading={loading} pagination={{ pageSize: 20 }}
              locale={{ emptyText: "暂无扫描任务" }}
            />
          )
        },
      ]} onTabClick={(key) => { if (key === "tasks") fetchTasks() }} />
    </div>
  )
}
