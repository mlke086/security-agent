import { useState, useEffect } from "react"
import { showError } from "../utils/showError"
import { Card, List, Tag, Statistic, Row, Col, Button, Input, Space, Empty, Spin, Progress } from "antd"
import { SearchOutlined, ArrowLeftOutlined } from "@ant-design/icons"
import { useSearchParams, useNavigate } from "react-router-dom"
import Markdown from "../components/Markdown"
import "../components/Markdown.css"
import AiEvidenceBadge from "../components/AiEvidenceBadge"
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
    } catch (err) { showError(err, "报告未找到，任务可能尚未完成") }
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

  // Build chart data (S-P2-16: precompute label->key so color lookup is O(1))
  const sevColorByLabel: Record<string, string> = Object.fromEntries(
    Object.entries(SEVERITY_LABEL).map(([k, label]) => [label, k]),
  )
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
        {report.summary && <div style={{ fontSize: 16, fontWeight: 500, marginBottom: 8 }}><Markdown source={report.summary} /></div>}
        {report.ai_analysis && <div style={{ color: "#666", marginBottom: 8 }}><Markdown source={report.ai_analysis} /></div>}
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
        <Col span={24}>
          <Card title="AI 建议" size="small">
            <Space direction="vertical" style={{ width: "100%" }} size="middle">
              <Space>
                <AiEvidenceBadge
                  aiProcessed={report.ai_processed}
                  aiModel={report.ai_model}
                  aiReason={!report.ai_processed ? "LLM 不可用，建议重新扫描以获取 AI 总体建议" : null}
                />
                {report.ai_processed_at && (
                  <span style={{ color: "#999", fontSize: 12 }}>生成于 {report.ai_processed_at}</span>
                )}
              </Space>
              {report.ai_overall_advice ? (
                <div style={{ background: "#fffbe6", padding: 12, borderRadius: 6, borderLeft: "3px solid #faad14" }}>
                  <div style={{ fontWeight: 500, marginBottom: 4 }}>AI 总体建议</div>
                  <Markdown source={report.ai_overall_advice} />
                </div>
              ) : (
                <div style={{ color: "#999" }}>
                  {report.ai_processed ? "AI 已处理但本报告未生成总体建议" : "AI 未处理，未生成总体建议"}
                </div>
              )}
              {report.ai_analysis && (
                <div style={{ background: "#fafafa", padding: 12, borderRadius: 6 }}>
                  <div style={{ fontWeight: 500, marginBottom: 4 }}>AI 分析摘要</div>
                  <Markdown source={report.ai_analysis} />
                </div>
              )}
            </Space>
          </Card>
        </Col>
      </Row>

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
                    <Progress percent={Math.round((s.value / max) * 100)} strokeColor={SEVERITY_COLORS[sevColorByLabel[s.type]] || "#1677ff"} showInfo={false} size="small" />
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

      {/* Top 漏洞 (2026-07-31 UX upgrade):
         - 严重等级徽章 + 名称 + 主机：单行排版，超过部分省略
         - 分类/CVE + 修复建议 上下位置，不重叠
         - 名称里的换行折叠成空格，避免奇怪换行 */}
      <Card title="Top 漏洞" style={{ marginBottom: 16 }}>
        {(report.top_vulns || []).length === 0 ? (
          <Empty description="未发现漏洞" />
        ) : (
          <List
            dataSource={report.top_vulns}
            split
            renderItem={(item: any) => {
              const sev = item.ai_severity || item.severity || 'info'
              const flatName = String(item.name || '').replace(/[\r\n]+/g, ' ').trim()
              const cveLabel = item.cve
                ? `CVE: ${item.cve}`
                : (item.category === 'baseline' || !item.cve ? '基线检查' : '漏洞详情')
              return (
                <List.Item style={{ alignItems: 'flex-start', padding: '12px 0' }}>
                  <div style={{ width: '100%' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <Tag color={SEVERITY_COLORS[sev] || 'default'} style={{ flex: '0 0 auto' }}>
                        {SEVERITY_LABEL[sev] || sev}
                      </Tag>
                      <span
                        title={flatName}
                        style={{
                          flex: '1 1 auto',
                          minWidth: 0,
                          fontWeight: 500,
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {flatName}
                      </span>
                      {item.hostname && (
                        <Tag style={{ flex: '0 0 auto' }} color="geekblue">{item.hostname}</Tag>
                      )}
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'baseline', color: '#666', fontSize: 13 }}>
                      <span style={{ color: '#999' }}>{cveLabel}</span>
                      {item.category && (
                        <Tag style={{ fontSize: 11, margin: 0 }} color="default">
                          {item.category === 'baseline' ? '基线' : item.category === 'sys_vuln' ? '漏洞' : item.category}
                        </Tag>
                      )}
                    </div>
                    {item.fix_advice && (
                      <div style={{ marginTop: 6, color: '#444', fontSize: 13, lineHeight: 1.6 }}>
                        <span style={{ color: '#999', marginRight: 4 }}>修复建议:</span>
                        <span style={{ wordBreak: 'break-word' }}>{item.fix_advice}</span>
                      </div>
                    )}
                  </div>
                </List.Item>
              )
            }}
          />
        )}
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
