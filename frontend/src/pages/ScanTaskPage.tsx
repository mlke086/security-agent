import { useState, useEffect } from "react"
import { Card, Tabs, Form, Input, Button, Select, message, Table, Tag, Popconfirm } from "antd"
import { ThunderboltOutlined, MessageOutlined, DeleteOutlined } from "@ant-design/icons"
import { useNavigate } from "react-router-dom"
import api from "../api/client"
import { deleteScanTask } from "../api/client"
import TargetSelector from "../components/TargetSelector"
import ChatScan from "../components/ChatScan"

interface ScanTask { task_id: string; source: string; targets: string[]; status: string; created_at: string; stats: { total: number; done: number; failed: number } }

export default function ScanTaskPage() {
  const [submitting, setSubmitting] = useState(false)
  const [tasks, setTasks] = useState<ScanTask[]>([])
  const [loading, setLoading] = useState(false)
  // 受控 tab：默认 tasks（用户从监控页返回时停留在任务列表，而非对话式）。
  const [activeTab, setActiveTab] = useState("tasks")
  const navigate = useNavigate()

  // mount 时默认在 tasks tab，自动加载任务列表
  useEffect(() => { fetchTasks() }, [])

  const handleSubmit = async (source: string, extra?: any) => {
    setSubmitting(true)
    try {
      const body: any = { source }
      body.targets = extra?.targets || []
      body.modules = extra?.modules || ["sys_vuln", "baseline"]
      body.engine = extra?.engine || "matcher"
      body.nuclei_severity = extra?.nuclei_severity || []
      body.nuclei_tags = extra?.nuclei_tags || []
      body.nuclei_templates = extra?.nuclei_templates || []
      body.nuclei_timeout_sec = extra?.nuclei_timeout_sec || 0
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

  const handleDeleteTask = async (taskId: string) => {
    try {
      await deleteScanTask(taskId)
      message.success("任务记录已删除")
      fetchTasks()
    } catch { message.error("删除失败") }
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
    { title: "操作", key: "action", width: 140, render: (_: any, r: ScanTask) => (
      <>
        <Button size="small" type="link" onClick={() => navigate(`/scan-monitor/${r.task_id}`)}>监控</Button>
        <Popconfirm title="删除该任务记录?" description="将删除任务及关联结果/漏洞/报告" onConfirm={() => handleDeleteTask(r.task_id)}>
          <Button size="small" type="link" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      </>
    )},
  ]

  return (
    <div>
      <Tabs activeKey={activeTab} onChange={(k) => {
        setActiveTab(k)
        if (k === "tasks") fetchTasks()
      }} items={[
        {
          key: "dialog", label: <span><MessageOutlined /> 对话式</span>, children: (
            <ChatScan />
          )
        },
        {
          key: "manual", label: <span><ThunderboltOutlined /> 手动</span>, children: (
            <Card>
              <Form
                onFinish={(v) => handleSubmit("manual", {
                  targets: v.targets || [],
                  modules: v.modules,
                  engine: v.engine,
                  nuclei_severity: v.nuclei_severity,
                  nuclei_tags: v.nuclei_tags,
                  nuclei_templates: v.nuclei_templates ? v.nuclei_templates.split(",").map((s: string) => s.trim()) : [],
                  nuclei_timeout_sec: v.nuclei_timeout_sec,
                })}
                initialValues={{
                  modules: ["sys_vuln", "baseline"],
                  engine: "matcher",
                  nuclei_severity: [],
                  nuclei_tags: [],
                  nuclei_templates: "",
                  nuclei_timeout_sec: 0,
                }}
              >
                <Form.Item name="targets" label="目标主机" rules={[{ required: true, message: "请选择目标主机或主机组" }]}>
                  <TargetSelector />
                </Form.Item>
                <Form.Item name="modules" label="扫描模块">
                  <Select mode="multiple" options={[{ label: "系统漏洞", value: "sys_vuln" }, { label: "安全基线", value: "baseline" }]} />
                </Form.Item>
                <Form.Item name="engine" label="扫描引擎" tooltip="matcher: 内部规则匹配器；nuclei: projectdiscovery/nuclei 10000+ 模板">
                  <Select
                    options={[
                      { label: "matcher (内部规则)", value: "matcher" },
                      { label: "nuclei (CVE 模板)", value: "nuclei" },
                    ]}
                  />
                </Form.Item>
                <Form.Item
                  noStyle
                  shouldUpdate={(prev, cur) => prev.engine !== cur.engine}
                >
                  {({ getFieldValue }) =>
                    getFieldValue("engine") === "nuclei" ? (
                      <>
                        <Form.Item name="nuclei_severity" label="严重等级">
                          <Select
                            mode="multiple"
                            options={["critical", "high", "medium", "low", "info"].map((v) => ({ label: v, value: v }))}
                            placeholder="留空 = 全部"
                          />
                        </Form.Item>
                        <Form.Item name="nuclei_tags" label="标签">
                          <Select
                            mode="tags"
                            options={[
                              { label: "rce", value: "rce" },
                              { label: "auth-bypass", value: "auth-bypass" },
                              { label: "sqli", value: "sqli" },
                              { label: "exposure", value: "exposure" },
                            ]}
                            placeholder="例: rce, auth-bypass"
                          />
                        </Form.Item>
                        <Form.Item name="nuclei_templates" label="模板 ID 列表" tooltip="逗号分隔，留空 = 全部已安装模板">
                          <Input placeholder="cves/2024/CVE-2024-1234, exposures/..." />
                        </Form.Item>
                        <Form.Item name="nuclei_timeout_sec" label="超时 (秒)">
                          <Input type="number" placeholder="0 = runner 默认 (600s)" />
                        </Form.Item>
                      </>
                    ) : null
                  }
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
            <>
              <div style={{ marginBottom: 12 }}>
                <Button onClick={fetchTasks} loading={loading}>刷新</Button>
              </div>
              <Table dataSource={tasks} columns={columns} rowKey="task_id" loading={loading} pagination={{ pageSize: 20 }}
                locale={{ emptyText: "暂无扫描任务" }}
              />
            </>
          )
        },
      ]} />
    </div>
  )
}
