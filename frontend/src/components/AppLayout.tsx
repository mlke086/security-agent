import { useState } from "react"
import { Layout, Menu, Button, Typography, theme, message } from "antd"
import {
  DashboardOutlined, ProfileOutlined, AuditOutlined,
  LogoutOutlined, SecurityScanOutlined, BugOutlined,
  CloudServerOutlined, EyeOutlined, FileSearchOutlined,
  SyncOutlined,
} from "@ant-design/icons"
import { useNavigate, useLocation, Outlet } from "react-router-dom"
import { useAuth } from "../context/AuthContext"
import { seedDemo } from "../api/client"

const { Header, Sider, Content } = Layout

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [seeding, setSeeding] = useState(false)
  const { token: themeToken } = theme.useToken()
  const role = user?.role || ""

  const isAdmin = role === "admin"
  const canApprove = role === "admin" || role === "responder"

  const items = [
    { key: "/", icon: <DashboardOutlined />, label: "运营大屏" },
    { key: "/hosts", icon: <CloudServerOutlined />, label: "主机纳管" },
    { key: "/scan", icon: <BugOutlined />, label: "扫描任务" },
    { key: "/vulns", icon: <EyeOutlined />, label: "漏洞清单" },
    { key: "/report", icon: <FileSearchOutlined />, label: "扫描报告" },
    { key: "/rules", icon: <SyncOutlined />, label: "规则管理" },
    { key: "/events", icon: <ProfileOutlined />, label: "事件队列" },
    ...(canApprove ? [{ key: "/approvals", icon: <AuditOutlined />, label: "审批列表" }] : []),
  ]

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark">
        <div style={{ height: 64, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontSize: collapsed ? 14 : 16, fontWeight: "bold" }}>
          <SecurityScanOutlined style={{ marginRight: collapsed ? 0 : 8 }} />
          {!collapsed && "SecAgent"}
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[location.pathname]} items={items} onClick={({ key }) => navigate(key)} />
      </Sider>
      <Layout>
        <Header style={{ background: themeToken.colorBgContainer, padding: "0 24px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid #f0f0f0" }}>
          <Typography.Text type="secondary">
            {role === "admin" ? "管理员" : role === "analyst" ? "分析师" : role === "responder" ? "响应员" : "观察者"}
          </Typography.Text>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {isAdmin && (
              <Button size="small" icon={<BugOutlined />} loading={seeding} onClick={async () => {
                setSeeding(true); try { await seedDemo(); message.success("演示数据已注入") } catch { message.error("注入失败") } finally { setSeeding(false) }
              }}>注入演示数据</Button>
            )}
            <Typography.Text style={{ marginRight: 8 }}>{user?.username}</Typography.Text>
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