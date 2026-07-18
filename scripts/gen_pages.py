import os

base = r"V:/project/security-agent/frontend/src"
files = {}

# App.tsx
files["App.tsx"] = """import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import AppLayout from './components/AppLayout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import EventQueuePage from './pages/EventQueuePage'
import TracePage from './pages/TracePage'
import { Spin } from 'antd'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { token, loading } = useAuth()
  if (loading) return <Spin size="large" style={{ display: 'block', margin: '200px auto' }} />
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/events" element={<EventQueuePage />} />
          <Route path="/trace" element={<TracePage />} />
          <Route path="/approve" element={<TracePage />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}
"""

# App.css
files["App.css"] = """body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
"""

# pages/DashboardPage.tsx
files["pages/DashboardPage.tsx"] = """import { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Typography, Spin, Table, Tag } from 'antd'
import { AlertOutlined, CheckCircleOutlined, CloseCircleOutlined, ClockCircleOutlined } from '@ant-design/icons'
import { getMetrics } from '../api/client'
import { useNavigate } from 'react-router-dom'

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    getMetrics().then(setMetrics).catch(() => {}).finally(() => setLoading(false))
  }, [])

  if (loading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />

  return (
    <div>
      <Typography.Title level={4}>运营大屏</Typography.Title>
      <Row gutter={[16, 16]}>
        <Col span={6}>
          <Card onClick={() => navigate('/events')} style={{ cursor: 'pointer' }}>
            <Statistic title="总事件数" value={metrics?.total_events || 0} prefix={<AlertOutlined />} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已批准" value={metrics?.events_by_status?.approved || 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已拒绝" value={metrics?.events_by_status?.rejected || 0} prefix={<CloseCircleOutlined />} valueStyle={{ color: '#ff4d4f' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="总审批数" value={metrics?.total_approvals || 0} prefix={<ClockCircleOutlined />} />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
"""

# pages/EventQueuePage.tsx
files["pages/EventQueuePage.tsx"] = """import { useState } from 'react'
import { Card, Form, Input, Select, Button, Typography, message, Divider, Alert } from 'antd'
import { submitEvent } from '../api/client'

export default function EventQueuePage() {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [form] = Form.useForm()

  const onFinish = async (values: any) => {
    setLoading(true)
    setResult(null)
    try {
      const iocs: Record<string, string[]> = {}
      if (values.ips) iocs.ip = values.ips.split(',').map((s: string) => s.trim())
      if (values.domains) iocs.domains = values.domains.split(',').map((s: string) => s.trim())
      const data = await submitEvent(values.sanitized_text, iocs, values.source)
      setResult(data)
      message.success(`事件已提交: ${data.event_id}`)
    } catch (err: any) {
      message.error(err.response?.data?.detail || '提交失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Typography.Title level={4}>事件队列 — 提交新事件</Typography.Title>
      <Card style={{ maxWidth: 800 }}>
        <Form form={form} layout="vertical" onFinish={onFinish}>
          <Form.Item name="sanitized_text" label="事件描述" rules={[{ required: true, message: '请输入事件描述' }]}>
            <Input.TextArea rows={4} placeholder="例如: Honeypot captured whoami from 45.33.32.156" />
          </Form.Item>
          <Form.Item name="source" label="来源" initialValue="api">
            <Select options={[
              { value: 'api', label: 'API' },
              { value: 'honeypot', label: '蜜罐' },
              { value: 'waf', label: 'WAF' },
              { value: 'ids', label: 'IDS' },
              { value: 'edr', label: 'EDR' },
            ]} />
          </Form.Item>
          <Form.Item name="ips" label="IOC IP列表（逗号分隔）">
            <Input placeholder="45.33.32.156, 8.8.8.8" />
          </Form.Item>
          <Form.Item name="domains" label="IOC 域名列表（逗号分隔）">
            <Input placeholder="evil.com, malware.net" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={block} block>提交事件</Button>
        </Form>
      </Card>

      {result && (
        <>
          <Divider />
          <Alert type="success" message="事件处理结果" description={JSON.stringify(result, null, 2)} />
        </>
      )}
    </div>
  )
}
"""

# pages/TracePage.tsx
files["pages/TracePage.tsx"] = """import { useState } from 'react'
import { Card, Input, Button, Typography, Spin, Descriptions, Tag, Timeline, message, Space } from 'antd'
import { SearchOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons'
import { getEventTrace, approveEvent } from '../api/client'
import { useLocation } from 'react-router-dom'

export default function TracePage() {
  const [eventId, setEventId] = useState('')
  const [trace, setTrace] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [approving, setApproving] = useState(false)
  const query = new URLSearchParams(useLocation().search)
  const initialId = query.get('id') || ''

  const search = async (id: string) => {
    if (!id) return
    setLoading(true)
    try {
      const data = await getEventTrace(id)
      setTrace(data)
    } catch {
      message.error('获取轨迹失败')
    }
    setLoading(false)
  }

  const handleApprove = async (action: 'approved' | 'rejected') => {
    if (!eventId && !initialId) return
    setApproving(true)
    try {
      await approveEvent(eventId || initialId, action)
      message.success(action === 'approved' ? '已批准' : '已拒绝')
      if (eventId || initialId) search(eventId || initialId)
    } catch {
      message.error('审批操作失败')
    }
    setApproving(false)
  }

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Typography.Title level={4} style={{ margin: 0 }}>推理轨迹 / 审批</Typography.Title>
      </Space>
      <Card>
        <Input.Search
          placeholder="输入事件 ID"
          enterButton={<><SearchOutlined /> 查询</>}
          size="large"
          defaultValue={initialId}
          onSearch={(val) => { setEventId(val); search(val) }}
          style={{ maxWidth: 500 }}
        />
      </Card>

      {loading && <Spin size="large" style={{ display: 'block', margin: '40px auto' }} />}

      {trace && (
        <Card style={{ marginTop: 16 }}>
          <Descriptions title="事件信息" column={2} bordered size="small">
            <Descriptions.Item label="事件 ID">{trace.event_id}</Descriptions.Item>
            <Descriptions.Item label="轨迹数">{trace.trace_count}</Descriptions.Item>
            <Descriptions.Item label="审批数">{trace.approval_count}</Descriptions.Item>
          </Descriptions>

          {trace.approvals?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <Typography.Text strong>审批记录</Typography.Text>
              <Timeline items={trace.approvals.map((a: any) => ({
                color: a.action === 'approved' ? 'green' : 'red',
                children: (
                  <div>
                    <Tag color={a.action === 'approved' ? 'success' : 'error'}>{a.action}</Tag>
                    <span>{a.actor} ({a.role})</span>
                    <div style={{ fontSize: 12, color: '#999' }}>{new Date(a.timestamp).toLocaleString()}</div>
                  </div>
                ),
              }))} />
            </div>
          )}

          <Space style={{ marginTop: 16 }}>
            <Button type="primary" icon={<CheckOutlined />} onClick={() => handleApprove('approved')} loading={approving}>批准</Button>
            <Button danger icon={<CloseOutlined />} onClick={() => handleApprove('rejected')} loading={approving}>拒绝</Button>
          </Space>
        </Card>
      )}
    </div>
  )
}
"""

for path, content in files.items():
    full = os.path.join(base, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(content.lstrip('\n'))
    print(f'Created: {path}')

print(f'\n{len(files)} files created')
