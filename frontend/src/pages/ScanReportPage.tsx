import { useState } from "react"
import { Card, List, Tag, Statistic, Row, Col, Button, Input, Space, message, Empty, Spin } from "antd"
import { SearchOutlined, PieChartOutlined } from "@ant-design/icons"
import { Pie, Bar } from "@ant-design/charts"
import api from "../api/client"



const SEVERITY_COLORS: Record<string, string> = {
  critical: "#cf1322", high: "#d4380d", medium: "#d4b106", low: "#389e0d", info: "#1677ff",
}

export default function ScanReportPage() {
  const [taskId, setTaskId] = useState("")
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const fetchReport = async () => {
    if (!taskId.trim()) return
    setLoading(true)
    try {
      const res = await api.get("/vulnscan/reports/" + taskId)
      setReport(res.data)
    } catch { message.error("Report not found") }
    finally { setLoading(false) }
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "200px auto" }} />

  if (!report) {
    return (
      <Card style={{ maxWidth: 500, margin: "100px auto", textAlign: "center" }}>
        <Space>
          <Input placeholder="Enter task ID" value={taskId} onChange={e => setTaskId(e.target.value)} onPressEnter={fetchReport} style={{ width: 260 }} />
          <Button type="primary" icon={<SearchOutlined />} onClick={fetchReport}>Query</Button>
        </Space>
      </Card>
    )
  }

  // Build chart data
  const sevData = Object.entries(report.stats?.by_severity || {}).map(([k, v]) => ({
    type: k, value: v,
  }))
  const catData = Object.entries(report.stats?.by_category || {}).map(([k, v]) => ({
    category: k === "sys_vuln" ? "System Vulns" : k === "baseline" ? "Baseline" : k, value: v,
  }))

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <Space>
          <Input placeholder="Task ID" value={taskId} onChange={e => setTaskId(e.target.value)} onPressEnter={fetchReport} style={{ width: 260 }} />
          <Button type="primary" icon={<SearchOutlined />} onClick={fetchReport}>Query</Button>
        </Space>
      </Card>

      {/* Summary Card */}
      <Card title="Scan Summary" style={{ marginBottom: 16 }}>
        {report.summary && <div style={{ fontSize: 16, fontWeight: 500, marginBottom: 8 }}>{report.summary}</div>}
        {report.ai_analysis && <div style={{ color: "#666", marginBottom: 8 }}>{report.ai_analysis}</div>}
        <Row gutter={16} style={{ marginTop: 16 }}>
          <Col span={4}><Statistic title="Critical" value={report.stats?.by_severity?.critical || 0} valueStyle={{ color: "#cf1322" }} /></Col>
          <Col span={4}><Statistic title="High" value={report.stats?.by_severity?.high || 0} valueStyle={{ color: "#d4380d" }} /></Col>
          <Col span={4}><Statistic title="Medium" value={report.stats?.by_severity?.medium || 0} valueStyle={{ color: "#d4b106" }} /></Col>
          <Col span={4}><Statistic title="Low" value={report.stats?.by_severity?.low || 0} valueStyle={{ color: "#389e0d" }} /></Col>
          <Col span={4}><Statistic title="Info" value={report.stats?.by_severity?.info || 0} valueStyle={{ color: "#1677ff" }} /></Col>
          <Col span={4}><Statistic title="Filtered Out" value={report.stats?.filtered_out || 0} valueStyle={{ color: "#999" }} /></Col>
        </Row>
      </Card>

      {/* Charts */}
      {sevData.length > 0 && (
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={12}>
            <Card title={<span><PieChartOutlined /> Severity Distribution</span>} size="small">
              <Pie
                data={sevData}
                angleField="value"
                colorField="type"
                radius={0.8}
                label={{ type: "outer", content: "{name} ({percentage})" }}
                color={["#cf1322", "#d4380d", "#d4b106", "#389e0d", "#1677ff"]}
                height={280}
              />
            </Card>
          </Col>
          <Col span={12}>
            <Card title="Category Distribution" size="small">
              <Bar
                data={catData}
                xField="value"
                yField="category"
                colorField="category"
                height={280}
                legend={false}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* Top Vulns */}
      <Card title="Top Vulnerabilities" style={{ marginBottom: 16 }}>
        <List
          dataSource={report.top_vulns || []}
          renderItem={(item: any) => (
            <List.Item
              extra={<Tag color={SEVERITY_COLORS[item.severity] || "default"}>{item.ai_severity || item.severity}</Tag>}
            >
              <List.Item.Meta
                title={<span>{item.name} <Tag style={{ marginLeft: 8 }}>{item.hostname}</Tag></span>}
                description={item.cve ? `CVE: ${item.cve}` : "Baseline check"}
              />
              {item.fix_advice && <div style={{ color: "#666", fontSize: 13, marginTop: 4 }}>Fix: {item.fix_advice}</div>}
            </List.Item>
          )}
          locale={{ emptyText: <Empty description="No vulnerabilities found" /> }}
        />
      </Card>

      {/* Recommendations */}
      <Card title="Recommendations">
        <List
          dataSource={report.recommendations || []}
          renderItem={(item: string, i: number) => (
            <List.Item>
              <Tag color="blue" style={{ marginRight: 8 }}>{i + 1}</Tag>
              {item}
            </List.Item>
          )}
        />
      </Card>
    </div>
  )
}
