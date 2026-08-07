import { useEffect, useRef, useState } from "react"
import { Card, Drawer, Empty, Segmented, Spin, Statistic, Col, Row, Alert } from "antd"
import { Line } from "@ant-design/charts"
import { getHostMetrics, type HostMetricPoint, type HostMetricsResp, type Host } from "../api/client"
import { showError } from "../utils/showError"
import { formatBeijing } from "../utils/time"

type MetricRange = "1h" | "24h" | "7d"

const RANGE_OPTIONS = [
  { label: "1 小时", value: "1h" },
  { label: "24 小时", value: "24h" },
  { label: "7 天", value: "7d" },
]

interface HostPerfDrawerProps {
  host: Host | null
  open: boolean
  onClose: () => void
}

/**
 * 主机性能监控抽屉（需求① Agent 性能监控）。
 *
 * 顶部为最新快照迷你卡片（cpu/mem/disk），下方按 1h/24h/7d 切换
 * 折线图（7d 为服务端 5m 降采样点）。数据来自 GET /agents/{id}/metrics。
 * 旧版本 Agent 不上报 host_metrics 时显示"未上报"提示。
 */
export default function HostPerfDrawer({ host, open, onClose }: HostPerfDrawerProps) {
  const [range, setRange] = useState<MetricRange>("24h")
  const [data, setData] = useState<HostMetricsResp | null>(null)
  const [loading, setLoading] = useState(false)
  // 卸载守卫：Drawer 关闭后 in-flight 响应不再 setState（防泄漏，同
  // HostOnboardPage 的 mountedRef 模式）。
  const aliveRef = useRef(true)

  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
    }
  }, [])

  useEffect(() => {
    if (!open || !host) return
    setLoading(true)
    getHostMetrics(host.agent_id, range)
      .then((r) => {
        if (aliveRef.current) setData(r)
      })
      .catch((err) => {
        if (aliveRef.current) showError(err, "加载性能数据失败")
      })
      .finally(() => {
        if (aliveRef.current) setLoading(false)
      })
  }, [open, host, range])

  const latest = data?.latest
  const points = data?.points ?? []
  const hasData = points.length > 0

  const toSeries = (field: keyof Pick<HostMetricPoint, "cpu" | "mem" | "disk" | "load1">) =>
    points
      .filter((p) => p[field] !== null && p[field] !== undefined)
      .map((p) => ({ ts: p.ts, value: p[field] as number }))

  const netSeries = [
    ...points.filter((p) => p.net_in !== null).map((p) => ({ ts: p.ts, type: "入站", value: p.net_in as number })),
    ...points.filter((p) => p.net_out !== null).map((p) => ({ ts: p.ts, type: "出站", value: p.net_out as number })),
  ]

  const lineConfig = (yTitle: string, max?: number) => ({
    height: 200,
    xField: "ts",
    yField: "value",
    smooth: true,
    yAxis: {
      title: { text: yTitle },
      ...(max ? { max } : {}),
    },
    tooltip: { title: (d: { ts: string }) => formatBeijing(d.ts) },
  } as const)

  const rangeSwitch = (
    <Segmented
      value={range}
      onChange={(v) => setRange(v as MetricRange)}
      options={RANGE_OPTIONS}
    />
  )

  return (
    <Drawer
      title={host ? `性能监控 - ${host.hostname} (${host.agent_id})` : "性能监控"}
      open={open}
      onClose={onClose}
      width={760}
      extra={rangeSwitch}
    >
      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spin /></div>
      ) : !hasData ? (
        <Empty description="暂无性能数据。Agent 版本过低（< 性能监控版）或尚未上报 host_metrics" />
      ) : (
        <>
          {/* 顶部迷你卡片：最新快照 */}
          <Row gutter={16} style={{ marginBottom: 16 }}>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title="CPU"
                  value={latest?.cpu ?? undefined}
                  precision={1}
                  suffix="%"
                  valueStyle={{ color: (latest?.cpu ?? 0) > 90 ? "#cf1322" : undefined }}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title="内存"
                  value={latest?.mem ?? undefined}
                  precision={1}
                  suffix="%"
                  valueStyle={{ color: (latest?.mem ?? 0) > 90 ? "#cf1322" : undefined }}
                />
                {latest?.mem_total_mb ? (
                  <div style={{ color: "#999", fontSize: 12, marginTop: 4 }}>
                    {Math.round((latest.mem_used_mb ?? 0) / 1024)} / {Math.round(latest.mem_total_mb / 1024)} GB
                  </div>
                ) : null}
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title="磁盘"
                  value={latest?.disk ?? undefined}
                  precision={1}
                  suffix="%"
                  valueStyle={{ color: (latest?.disk ?? 0) > 90 ? "#cf1322" : undefined }}
                />
                {latest?.disk_total_gb ? (
                  <div style={{ color: "#999", fontSize: 12, marginTop: 4 }}>
                    {Math.round(latest.disk_used_gb ?? 0)} / {Math.round(latest.disk_total_gb)} GB
                  </div>
                ) : null}
              </Card>
            </Col>
          </Row>

          {latest?.load1 !== undefined && latest?.load1 !== null && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message={`负载 load1: ${latest.load1}`}
            />
          )}

          <Card title="CPU 使用率 (%)" size="small" style={{ marginBottom: 16 }}>
            <Line {...lineConfig("CPU %", 100)} data={toSeries("cpu")} />
          </Card>
          <Card title="内存使用率 (%)" size="small" style={{ marginBottom: 16 }}>
            <Line {...lineConfig("内存 %", 100)} data={toSeries("mem")} />
          </Card>
          <Card title="磁盘使用率 (%)" size="small" style={{ marginBottom: 16 }}>
            <Line {...lineConfig("磁盘 %", 100)} data={toSeries("disk")} />
          </Card>
          <Card title="网络吞吐 (KB/s)" size="small">
            {netSeries.length ? (
              <Line
                {...lineConfig("KB/s")}
                seriesField="type"
                data={netSeries}
                legend={{ position: "top" }}
              />
            ) : (
              <Empty description="暂无网络数据" />
            )}
          </Card>
        </>
      )}
    </Drawer>
  )
}
