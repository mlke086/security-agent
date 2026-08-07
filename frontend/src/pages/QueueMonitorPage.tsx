import { useCallback, useEffect, useState } from "react"
import {
  Alert, Button, Card, Col, Form, InputNumber, message, Popconfirm, Row, Space, Statistic, Switch, Table, Tag, Typography, Tooltip,
} from "antd"
import { ReloadOutlined, DeleteOutlined, ThunderboltOutlined, RobotOutlined } from "@ant-design/icons"
import {
  getTaskStats, getQueueStatus, getAlertConfig, putAlertConfig, releaseTasksBatch, getLlmUsage,
  type TaskStatusCount, type QueueStatusResp, type AlertConfig, type ReleaseResponse, type LlmUsageSummary,
} from "../api/client"
import { showError } from "../utils/showError"

const STATUS_COLORS: Record<string, string> = {
  queued: "orange",
  scanning: "blue",
  completed: "green",
  failed: "red",
  cancelled: "default",
}

const { Text } = Typography

export default function QueueMonitorPage() {
  const [stats, setStats] = useState<TaskStatusCount[]>([])
  const [queueStatus, setQueueStatus] = useState<QueueStatusResp | null>(null)
  const [alertCfg, setAlertCfg] = useState<AlertConfig | null>(null)
  const [llmUsage, setLlmUsage] = useState<LlmUsageSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [releasing, setReleasing] = useState<string[]>([])
  const [selectedRows, setSelectedRows] = useState<string[]>([])
  const [batchMsg, setBatchMsg] = useState<ReleaseResponse | null>(null)
  const [form] = Form.useForm()

  const fetchAll = useCallback(async () => {
    setLoading(true)
    try {
      const [s, q, c, l] = await Promise.all([getTaskStats(), getQueueStatus(), getAlertConfig(), getLlmUsage()])
      setStats(s)
      setQueueStatus(q)
      setAlertCfg(c)
      setLlmUsage(l)
      form.setFieldsValue({
        queued_threshold: c.queued_threshold,
        oldest_age_sec: Math.round(c.oldest_age_sec / 60),
        scan_check_enabled: c.scan_check_enabled,
        check_interval_sec: c.check_interval_sec,
      })
    } catch (e) {
      showError(e, "加载队列监控数据失败")
    } finally {
      setLoading(false)
    }
  }, [form])

  useEffect(() => { fetchAll(); const iv = setInterval(fetchAll, 15000); return () => clearInterval(iv) }, [fetchAll])

  const doReleaseBatch = async (ids: string[]) => {
    if (!ids.length) return
    setReleasing(ids)
    try {
      const resp = await releaseTasksBatch(ids)
      setBatchMsg(resp)
      const releasedIds = new Set(resp.items.filter(i => i.status === "released").map(i => i.task_id))
      const busyIds = resp.items.filter(i => i.status === "busy_scanning").map(i => i.task_id)
      if (releasedIds.size) message.success(`已释放 ${releasedIds.size} 个堆积任务`)
      if (busyIds.length) message.warning(`跳过 ${busyIds.length} 个扫描中的任务(不释放)`)
      await fetchAll()
    } catch (e) {
      showError(e, "释放失败")
    } finally {
      setReleasing([])
      setSelectedRows([])
    }
  }

  const saveConfig = async (values: Record<string, unknown>) => {
    if (!alertCfg) return
    try {
      await putAlertConfig({
        queued_threshold: Number(values.queued_threshold),
        oldest_age_sec: Number(values.oldest_age_sec) * 60,
        scan_check_enabled: Boolean(values.scan_check_enabled),
        check_interval_sec: Number(values.check_interval_sec),
      })
      message.success("告警阈值已保存")
      await fetchAll()
    } catch (e) {
      showError(e, "保存失败")
    }
  }

  const totalQueued = stats.find(s => s.status === "queued")?.count ?? 0
  const totalScanning = stats.find(s => s.status === "scanning")?.count ?? 0
  const totalFailed = stats.find(s => s.status === "failed")?.count ?? 0
  const oldestMin = queueStatus?.oldest_entry_age_sec != null ? Math.round(queueStatus.oldest_entry_age_sec / 60) : 0
  const overThreshold = alertCfg != null && (totalQueued >= alertCfg.queued_threshold || oldestMin * 60 >= alertCfg.oldest_age_sec)

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col span={6}><Card><Statistic title="排队中 (queued)" value={totalQueued} valueStyle={{ color: totalQueued ? "#fa8c16" : undefined }} /></Card></Col>
        <Col span={6}><Card><Statistic title="扫描中 (scanning)" value={totalScanning} valueStyle={{ color: "#1677ff" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="失败 (failed)" value={totalFailed} valueStyle={{ color: totalFailed ? "#ff4d4f" : undefined }} /></Card></Col>
        <Col span={6}><Card><Statistic title="最老任务等待 (min)" value={oldestMin} suffix="min" /></Card></Col>
      </Row>

      {overThreshold && (
        <Alert
          type="warning" showIcon style={{ marginBottom: 16 }}
          message="队列堆积告警"
          description={`排队任务 ${totalQueued} 个(阈值 ${alertCfg?.queued_threshold})或最老等待 ${oldestMin} 分钟(阈值 ${alertCfg ? Math.round(alertCfg.oldest_age_sec / 60) : 0} 分钟),已超阈值。可选中下方堆积任务释放。`}
        />
      )}

      <Card
        title={<Space><ThunderboltOutlined /> LLM 任务队列监控</Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={fetchAll} loading={loading}>刷新</Button>}
        style={{ marginBottom: 16 }}
      >
        <Row gutter={[16, 16]} style={{ marginBottom: 8 }}>
          <Col span={8}><Text type="secondary">Redis Stream: </Text><Text code>{queueStatus?.stream ?? "-"}</Text></Col>
          <Col span={4}><Text type="secondary">消息数: </Text><Text strong>{queueStatus?.xlen ?? 0}</Text></Col>
          <Col span={4}><Text type="secondary">pending: </Text><Text strong>{queueStatus?.pending ?? 0}</Text></Col>
          <Col span={4}><Text type="secondary">DLQ: </Text><Text strong>{queueStatus?.dlq_xlen ?? 0}</Text></Col>
          <Col span={4}><Text type="secondary">消费端: </Text><Text strong>{queueStatus?.pending_consumers ?? 0}</Text></Col>
        </Row>
        <Table<TaskStatusCount>
          size="small" rowKey="status" loading={loading}
          dataSource={stats}
          pagination={false}
          columns={[
            { title: "状态", dataIndex: "status", render: (s: string) => <Tag color={STATUS_COLORS[s] ?? "default"}>{s}</Tag> },
            { title: "数量", dataIndex: "count", render: (n: number) => <Text strong>{n}</Text> },
            { title: "说明", render: (_: unknown, row) => {
              if (row.status === "queued") return <Text type="secondary">等待 worker 消费;可安全释放</Text>
              if (row.status === "scanning") return <Text type="secondary">处理中,释放会被拒绝</Text>
              if (row.status === "failed") return <Text type="secondary">执行失败;可释放</Text>
              if (row.status === "completed") return <Text type="secondary">已完成;可释放</Text>
              return null
            } },
          ]}
        />
      </Card>

      <Card
        title="堆积任务操作"
        extra={
          <Space>
            <Popconfirm
              title="确认释放选中任务?"
              description={`将删除 ${selectedRows.length} 个任务的记录与队列消息(scanning 中将被跳过),不可恢复。`}
              onConfirm={() => doReleaseBatch(selectedRows)}
              disabled={!selectedRows.length}
            >
              <Button danger icon={<DeleteOutlined />} loading={!!releasing.length} disabled={!selectedRows.length}>批量释放</Button>
            </Popconfirm>
          </Space>
        }
      >
        {batchMsg && (
          <Alert
            style={{ marginBottom: 12 }} type="info" showIcon
            message={`释放结果:成功 ${batchMsg.released} / 失败 ${batchMsg.failed} / 扫描中跳过 ${batchMsg.busy} / 未找到 ${batchMsg.not_found}`}
          />
        )}
        <Text type="secondary">
          说明:任务默认保留在队列,不做自动丢弃。以下为当前排队/失败/已完成任务,可勾选后由你决定释放。
          释放会同时删除 ES 记录与 Redis 队列消息;扫描中的任务不会释放。
        </Text>
      </Card>

      {/* 2026-08-06 LLM 分析监控:漏洞分析/报告生成的超时·失败·重试 */}
      <Card
        title={<Space><RobotOutlined /> LLM 分析监控(漏洞分析 / 报告生成)</Space>}
        style={{ marginTop: 16 }}
        extra={
          <Space>
            <Tag color={llmUsage && llmUsage.active_calls > 0 ? "processing" : "default"}>
              {llmUsage ? `活跃调用 ${llmUsage.active_calls}` : "活跃调用 -"}
            </Tag>
          </Space>
        }
      >
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col span={4}><Card size="small"><Statistic title="总调用" value={llmUsage?.total_calls ?? 0} /></Card></Col>
          <Col span={4}><Card size="small"><Statistic title="成功" value={llmUsage?.success ?? 0} valueStyle={{ color: "#3f8600" }} /></Card></Col>
          <Col span={4}><Card size="small"><Statistic title="超时" value={llmUsage?.timeout ?? 0} valueStyle={{ color: llmUsage?.timeout ? "#cf1322" : undefined }} /></Card></Col>
          <Col span={4}><Card size="small"><Statistic title="失败" value={llmUsage?.failed ?? 0} valueStyle={{ color: llmUsage?.failed ? "#cf1322" : undefined }} /></Card></Col>
          <Col span={4}><Card size="small"><Statistic title="重试次数" value={llmUsage?.retried ?? 0} valueStyle={{ color: llmUsage?.retried ? "#fa8c16" : undefined }} /></Card></Col>
          <Col span={4}><Card size="small"><Statistic title="平均耗时" value={llmUsage?.avg_duration_ms ?? 0} suffix="ms" /></Card></Col>
        </Row>

        {llmUsage && llmUsage.by_kind && Object.keys(llmUsage.by_kind).length > 0 && (
          <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
            {Object.entries(llmUsage.by_kind).map(([kind, m]) => (
              <Col span={6} key={kind}>
                <Card size="small" title={<Text code>{kind}</Text>}>
                  <Space size={12} wrap>
                    <Tag color="green">成功 {m.success ?? 0}</Tag>
                    <Tag color="red">超时 {m.timeout ?? 0}</Tag>
                    <Tag color="red">失败 {m.failed ?? 0}</Tag>
                    <Tag color="orange">重试 {m.retry ?? 0}</Tag>
                  </Space>
                </Card>
              </Col>
            ))}
          </Row>
        )}

        {llmUsage && (llmUsage.timeout > 0 || llmUsage.failed > 0) && (
          <Alert
            type="warning" showIcon style={{ marginBottom: 12 }}
            message="LLM 分析存在超时/失败"
            description={`累计超时 ${llmUsage.timeout} 次、失败 ${llmUsage.failed} 次。失败的漏洞批次已进入待补扫队列,将在队列空闲时自动重试(最高 ${"配置上限"} 次)。`}
          />
        )}

        {llmUsage && llmUsage.outcomes.length > 0 && (
          <Alert
            type="error" showIcon style={{ marginBottom: 12 }}
            message="部分任务 AI 分析未完成"
            description={llmUsage.outcomes.map(o => `${String(o.task_id).slice(0, 8)}…: ${String(o.reason)}(成功 ${o.succeeded}/${o.total})`).join("; ")}
          />
        )}

        {llmUsage && llmUsage.retry_pending.length > 0 && (
          <Table
            size="small" rowKey="task_id" style={{ marginTop: 8 }}
            title={() => <Text strong>待补扫批次({llmUsage.retry_pending.length} 个任务)</Text>}
            dataSource={llmUsage.retry_pending}
            pagination={false}
            columns={[
              { title: "任务 ID", dataIndex: "task_id", render: (v: string) => <Text code>{v.slice(0, 12)}…</Text> },
              { title: "待补扫 finding 数", dataIndex: "pending_batches" },
              {
                title: "明细",
                dataIndex: "entries",
                render: (entries: Array<{ finding_id: string; attempts: number }>) => (
                  <Tooltip title={entries.slice(0, 10).map(e => `${e.finding_id.slice(0, 12)}…(尝试 ${e.attempts} 次)`).join("\n")}>
                    <Tag color="orange">{entries.length} 个失败批次</Tag>
                  </Tooltip>
                ),
              },
            ]}
          />
        )}

        {llmUsage && llmUsage.failures_recent.length > 0 && (
          <Table
            size="small" rowKey={(r, i) => `${String(r.ts ?? "")}-${i ?? 0}`} style={{ marginTop: 12 }}
            title={() => <Text strong>最近失败明细(最近 {llmUsage.failures_recent.length} 条)</Text>}
            dataSource={llmUsage.failures_recent}
            pagination={{ pageSize: 5 }}
            columns={[
              { title: "时间", dataIndex: "ts", render: (v: string) => <Text type="secondary">{String(v).slice(0, 19).replace("T", " ")}</Text> },
              { title: "类型", dataIndex: "kind", render: (v: string) => <Tag>{v}</Tag> },
              { title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "timeout" ? "volcano" : "red"}>{v}</Tag> },
              { title: "耗时", dataIndex: "duration_ms", render: (v: number) => `${v}ms` },
              { title: "任务", dataIndex: "task_id", render: (v: unknown) => (v ? <Text code>{String(v).slice(0, 12)}…</Text> : "-") },
              { title: "错误", dataIndex: "error", ellipsis: true, render: (v: unknown) => <Text type="secondary">{String(v ?? "-").slice(0, 60)}</Text> },
            ]}
          />
        )}
      </Card>

      <Card title="告警阈值配置" style={{ marginTop: 16 }}>        <Form
          form={form}
          layout="inline"
          style={{ rowGap: 12 }}
          onFinish={saveConfig}
          initialValues={{ queued_threshold: 50, oldest_age_sec: 30, scan_check_enabled: true, check_interval_sec: 60 }}
        >
          <Form.Item name="queued_threshold" label="堆积任务数阈值" rules={[{ required: true }]}>
            <InputNumber min={1} max={10000} style={{ width: 120 }} />
          </Form.Item>
          <Form.Item name="oldest_age_sec" label="最老任务等待(分钟)" rules={[{ required: true }]}>
            <InputNumber min={1} max={1440} style={{ width: 120 }} />
          </Form.Item>
          <Form.Item name="check_interval_sec" label="检查间隔(秒)" rules={[{ required: true }]}>
            <InputNumber min={10} max={3600} style={{ width: 120 }} />
          </Form.Item>
          <Form.Item name="scan_check_enabled" label="启用周期扫描" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">保存</Button>
          </Form.Item>
        </Form>
        <div style={{ marginTop: 8 }}>
          <Text type="secondary">超阈值时 scan-engine 后台会打结构化告警日志(queue_alert_queued_threshold_exceeded / queue_alert_oldest_age_exceeded),由日志 pipeline 采集。</Text>
        </div>
      </Card>
    </div>
  )
}