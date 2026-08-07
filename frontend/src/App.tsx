import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import AppLayout from './components/AppLayout'
import ErrorBoundary from './components/ErrorBoundary'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import EventQueuePage from './pages/EventQueuePage'
import EventDetailPage from './pages/EventDetailPage'
import AlertInboxPage from './pages/AlertInboxPage'
import ApprovalsPage from './pages/ApprovalsPage'
import HostOnboardPage from './pages/HostOnboardPage'
import ScanTaskPage from './pages/ScanTaskPage'
import QueueMonitorPage from './pages/QueueMonitorPage'
import ScanMonitorPage from './pages/ScanMonitorPage'
import VulnListPage from './pages/VulnListPage'
import AssetScanPage from './pages/AssetScanPage'
import ScanReportPage from './pages/ScanReportPage'
import RulesPage from './pages/RulesPage'
import ModelsPage from './pages/ModelsPage'
import UsersPage from './pages/UsersPage'
import { Spin } from 'antd'

function ProtectedRoute({ children, adminOnly = false }: { children: React.ReactNode; adminOnly?: boolean }) {
  const { token, user, loading } = useAuth()
  if (loading) return <Spin size="large" style={{ display: 'block', margin: '200px auto' }} />
  if (!token) return <Navigate to="/login" replace />
  if (adminOnly && user?.role !== "admin") return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/events" element={<EventQueuePage />} />
    <Route path="/alerts" element={<AlertInboxPage />} />
            <Route path="/events/:eventId" element={<EventDetailPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/hosts" element={<HostOnboardPage />} />
            <Route path="/scan" element={<ScanTaskPage />} />
            <Route path="/queue-monitor" element={<QueueMonitorPage />} />
            <Route path="/scan-monitor/:taskId" element={<ScanMonitorPage />} />
            <Route path="/vulns" element={<VulnListPage />} />
 <Route path="/asset-scan" element={<AssetScanPage />} />
            <Route path="/report" element={<ScanReportPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/models" element={<ModelsPage />} />
            <Route path="/users" element={<ProtectedRoute adminOnly><UsersPage /></ProtectedRoute>} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </ErrorBoundary>
  )
}
