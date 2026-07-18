import os

base = r"V:/project/security-agent/frontend/src"

files = {}

# vite-env.d.ts
files["vite-env.d.ts"] = """/// <reference types="vite/client" />
"""

# main.tsx
files["main.tsx"] = """import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './App.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
"""

# api/client.ts
files["api/client.ts"] = """import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('role')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

export default api

export async function login(username: string, password: string) {
  const res = await api.post('/auth/login', { username, password })
  return res.data
}

export async function submitEvent(sanitizedText: string, iocs: Record<string, string[]>, source: string) {
  const res = await api.post('/events', { sanitized_text: sanitizedText, iocs, source })
  return res.data
}

export async function getEventTrace(eventId: string) {
  const res = await api.get(`/events/${eventId}/trace`)
  return res.data
}

export async function approveEvent(eventId: string, action: string, note: string = '') {
  const res = await api.post(`/events/${eventId}/approve`, null, { params: { action, note } })
  return res.data
}

export async function getMetrics() {
  const res = await api.get('/metrics')
  return res.data
}

export async function getMe() {
  const res = await api.get('/auth/me')
  return res.data
}
"""

# context/AuthContext.tsx
files["context/AuthContext.tsx"] = """import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import api from '../api/client'

interface User {
  username: string
  role: string
  disabled: boolean
}

interface AuthContextType {
  user: User | null
  token: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
}

const AuthContext = createContext<AuthContextType>(null!)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (token) {
      api.get('/auth/me')
        .then((res) => setUser(res.data))
        .catch(() => { localStorage.removeItem('token'); setToken(null) })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [token])

  const loginFn = async (username: string, password: string) => {
    const data = await login(username, password)
    localStorage.setItem('token', data.access_token)
    localStorage.setItem('role', data.role)
    setToken(data.access_token)
    const me = await api.get('/auth/me')
    setUser(me.data)
  }

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('role')
    setToken(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, token, login: loginFn, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

import { login } from '../api/client'

export const useAuth = () => useContext(AuthContext)
"""

# components/AppLayout.tsx
files["components/AppLayout.tsx"] = """import { useState } from 'react'
import { Layout, Menu, Button, Typography, theme } from 'antd'
import {
  DashboardOutlined, AuditOutlined, SearchOutlined,
  ProfileOutlined, LogoutOutlined, SecurityScanOutlined,
} from '@ant-design/icons'
import { useNavigate, useLocation, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const { Header, Sider, Content } = Layout

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '运营大屏' },
  { key: '/events', icon: <ProfileOutlined />, label: '事件队列' },
  { key: '/trace', icon: <SearchOutlined />, label: '推理轨迹' },
  { key: '/approve', icon: <AuditOutlined />, label: '审批列表' },
]

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const { token: themeToken } = theme.useToken()

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark">
        <div style={{ height: 64, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: collapsed ? 14 : 16, fontWeight: 'bold' }}>
          <SecurityScanOutlined style={{ marginRight: collapsed ? 0 : 8 }} />
          {!collapsed && 'SecAgent'}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header style={{ background: themeToken.colorBgContainer, padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #f0f0f0' }}>
          <Typography.Text type="secondary">
            {user?.role === 'admin' ? '管理员' : user?.role === 'analyst' ? '分析师' : user?.role === 'responder' ? '响应员' : '观察者'}
          </Typography.Text>
          <div>
            <Typography.Text style={{ marginRight: 16 }}>{user?.username}</Typography.Text>
            <Button type="text" icon={<LogoutOutlined />} onClick={logout}>退出</Button>
          </div>
        </Header>
        <Content style={{ margin: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
"""

# pages/LoginPage.tsx
files["pages/LoginPage.tsx"] = """import { useState } from 'react'
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
"""

for path, content in files.items():
    full = os.path.join(base, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(content.lstrip('\n'))
    print(f'Created: {path}')

print(f'\\n{len(files)} files created successfully')
