import { useState, useEffect } from "react"
import { Card, List, Tag, Statistic, Row, Col, Button, Input, Space, message, Empty, Spin, Progress } from "antd"
import { SearchOutlined, ArrowLeftOutlined } from "@ant-design/icons"
import { useSearchParams, useNavigate } from "react-router-dom"
import api from "../api/client"

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#cf1322", high: "#d4380d", medium: "#d4b106", low: "#389e0d", info: "#1677ff",
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示",
}

const CATEGORY_LABEL: Record<string, string> = {
  sys_vuln: "系统漏洞", baseline: "安全基线",
}

export default function ScanReportPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const [taskId, setTaskId] = useState("")
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const fetchReport = async (id?: string) => {
    const tid = (id ?? taskId).trim()
    if (!tid) return
    setLoading(true)
    try {
      const res = await api.get("/vulnscan/reports/" + tid)
      setReport(res.data)
    } catch { message.error("报告未找到，任务可能尚未完成") }
    finally { setLoading(false) }
  }

  // 支持从监控页带 ?taskId= 跳转自动查询
  useEffect(() => {
    const q = searchParams.get("taskId")
    if (q) {
      setTaskId(q)
      fetchReport(q)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  if (loading) return <Spin size="large" style={{ display: "block", margin: "200px auto" }} />

  if (!report) {
    return (
      <Card style={{ maxWidth: 500, margin: "100px auto", textAlign: "center" }}>
        <Space>
          <Input placeholder="请输入任务 ID" value={taskId} onChange={e => setTaskId(e.target.value)} onPressEnter={() => fetchReport()} style={{ width: 260 }} />
          <Button type="primary" icon={<SearchOutlined />} onClick={() => fetchReport()}>查询</Button>
        </Space>
      </Card>
    )
  }

  // Build chart data
  const sevData: { type: string; value: number }[] = Object.entries(report.stats?.by_severity || {}).map(([k, v]) => ({
    type: SEVERITY_LABEL[k] || k, value: Number(v) || 0,
  }))
  const catData: { category: string; value: number }[] = Object.entries(report.stats?.by_category || {}).map(([k, v]) => ({
    category: CATEGORY_LABEL[k] || k, value: Number(v) || 0,
  }))

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>返回</Button>
      </Space>
      <Card style={{ marginBottom: 16 }}>
        <Space>
          <Input placeholder="任务 ID" value={taskId} onChange={e => setTaskId(e.target.value)} onPressEnter={() => fetchReport()} style={{ width: 260 }} />
          <Button type="primary" icon={<SearchOutlined />} onClick={() => fetchReport()}>查询</Button>
        </Space>
      </Card>

      {/* 扫描摘要 */}
      <Card title="扫描摘要" style={{ marginBottom: 16 }}>
        {report.summary && <div style={{ fontSize: 16, fontWeight: 500, marginBottom: 8 }}>{report.summary}</div>}
        {report.ai_analysis && <div style={{ color: "#666", marginBottom: 8 }}>{report.ai_analysis}</div>}
        <Row gutter={16} style={{ marginTop: 16 }}>
          <Col span={4}><Statistic title="严重" value={report.stats?.by_severity?.critical || 0} valueStyle={{ color: "#cf1322" }} /></Col>
          <Col span={4}><Statistic title="高危" value={report.stats?.by_severity?.high || 0} valueStyle={{ color: "#d4380d" }} /></Col>
          <Col span={4}><Statistic title="中危" value={report.stats?.by_severity?.medium || 0} valueStyle={{ color: "#d4b106" }} /></Col>
          <Col span={4}><Statistic title="低危" value={report.stats?.by_severity?.low || 0} valueStyle={{ color: "#389e0d" }} /></Col>
          <Col span={4}><Statistic title="提示" value={report.stats?.by_severity?.info || 0} valueStyle={{ color: "#1677ff" }} /></Col>
          <Col span={4}><Statistic title="已过滤" value={report.stats?.filtered_out || 0} valueStyle={{ color: "#999" }} /></Col>
        </Row>
      </Card>

      {/* 图表 */}
      {/* 严重等级分布（antd Progress，避免 @ant-design/charts 动态加载报错） */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={12}>
          <Card title="严重等级分布" size="small">
            {sevData.length === 0 ? (
              <Empty description="无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              sevData.map((s) => {
                const max = Math.max(...sevData.map((x) => x.value), 1)
                return (
                  <div key={s.type} style={{ marginBottom: 8 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                      <span>{s.type}</span><span>{s.value}</span>
                    </div>
                    <Progress percent={Math.round((s.value / max) * 100)} strokeColor={SEVERITY_COLORS[Object.keys(SEVERITY_LABEL).find((k) => SEVERITY_LABEL[k] === s.type) || ""] || "#1677ff"} showInfo={false} size="small" />
                  </div>
                )
              })
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="分类分布" size="small">
            {catData.length === 0 ? (
              <Empty description="无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              catData.map((c) => {
                const max = Math.max(...catData.map((x) => x.value), 1)
                return (
                  <div key={c.category} style={{ marginBottom: 8 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                      <span>{c.category}</span><span>{c.value}</span>
                    </div>
                    <Progress percent={Math.round((c.value / max) * 100)} strokeColor="#1677ff" showInfo={false} size="small" />
                  </div>
                )
              })
            )}
          </Card>
        </Col>
      </Row>

      {/* Top 漏洞 */}
      <Card title="Top 漏洞" style={{ marginBottom: 16 }}>
        <List
          dataSource={report.top_vulns || []}
          renderItem={(item: any) => (
            <List.Item
              extra={<Tag color={SEVERITY_COLORS[item.severity] || "default"}>{SEVERITY_LABEL[item.ai_severity || item.severity] || item.ai_severity || item.severity}</Tag>}
            >
              <List.Item.Meta
                title={<span>{item.name} <Tag style={{ marginLeft: 8 }}>{item.hostname}</Tag></span>}
                description={item.cve ? `CVE: ${item.cve}` : "基线检查"}
              />
              {item.fix_advice && <div style={{ color: "#666", fontSize: 13, marginTop: 4 }}>修复建议: {item.fix_advice}</div>}
            </List.Item>
          )}
          locale={{ emptyText: <Empty description="未发现漏洞" /> }}
        />
      </Card>

      {/* 修复建议 */}
      <Card title="修复建议">
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
