import { useState } from 'react'
import { Card, Form, Input, Button, Typography, message, Space } from 'antd'
import { SecurityScanOutlined, UserOutlined, LockOutlined } from '@ant-design/icons'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)

  const onFinish = async (values: { username: string; password: string }) => {
    setLoading(true)
    try {
      await login(values.username, values.password)
      message.success('登录成功')
      navigate('/')
    } catch {
      message.error('用户名或密码错误')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f0f2f5' }}>
      <Card style={{ width: 400 }}>
        <Space direction="vertical" style={{ width: '100%', textAlign: 'center', marginBottom: 24 }}>
          <SecurityScanOutlined style={{ fontSize: 48, color: '#1677ff' }} />
          <Typography.Title level={3} style={{ margin: 0 }}>安全 AI Agent</Typography.Title>
          <Typography.Text type="secondary">安全事件智能分析平台</Typography.Text>
        </Space>
        <Form onFinish={onFinish} size="large">
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>登 录</Button>
          </Form.Item>
          <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', textAlign: 'center' }}>
            demo: admin / admin123
          </Typography.Text>
        </Form>
      </Card>
    </div>
  )
}
