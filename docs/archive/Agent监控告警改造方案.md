# Agent 监控告警 → 研判 → 响应 完整链路改造方案

> 生成日期：2026-07-26
> 目标：让现有 Go Agent 具备主机安全监控能力，打通 "Agent 监控采集 → 告警生成 → 智能研判 → 自动响应" 全链路，同时支持接入第三方 EDR 告警

---

## 一、现状分析

### 1.1 当前 Agent 能力（仅有这些）

| 能力 | 现状 | 代码位置 |
|------|------|---------|
| WebSocket 长连接 | ✅ 完善：心跳 + 重连 + 离线队列 | `agent/internal/comm/client.go` |
| Ed25519 签名通信 | ✅ 完善：指令/规则/升级包全部验签 | `agent/internal/crypto/verify.go` |
| 规则热加载 | ✅ 完善：下载规则包 → 内存热加载 | `agent/internal/updater/upgrade.go` |
| 漏洞扫描 | ✅ 完善：matcher 规则引擎 + Nuclei | `agent/internal/scan/engine.go` |
| 自升级 | ✅ 完善：原子替换 + ack-then-restart | `agent/internal/updater/upgrade.go` |
| 资源监控 | ❌ **极简**：仅有 goroutine/MemStats 粗略采样，用于扫描限流 | `agent/internal/resource/monitor.go` |
| 安全事件监控 | ❌ **完全空白**：无进程监控、无文件监控、无网络连接监控、无日志采集 | — |
| 检测规则引擎 | ❌ **空白**：只有 CVE 漏洞匹配规则，无行为检测/入侵检测规则 | — |

### 1.2 当前告警入口（仅支持外部推送）

```
Kafka raw-alerts ──► AlertConsumer ──► run_pipeline()
HTTP POST /events ──► BackgroundTask ──► run_pipeline()
```

**问题**：Agent 不能主动产生告警，只能被动接收外部系统推送。缺失 "Agent 端检测 → 告警上报" 这一段。

### 1.3 当前响应出口

```
run_pipeline() → LangGraph 主图 → responder 子图 → HITL 审批 → ActionDispatcher
```

响应能力已有 `notify / siem_tag / dns_block / simulator` 四个连接器，playbook 机制成熟。

---

## 二、可借鉴的开源项目

### 2.1 Elkeid（字节跳动）⭐ ~2,091

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/bytedance/Elkeid` |
| 语言 | Go (Agent/Server) + C (eBPF Driver) |
| 核心亮点 | **Go Agent + 插件架构**：Driver Plugin (内核数据采集)、Collector Plugin、Journal Watcher、Scanner Plugin (Yara)、RASP Plugin |
| 生产验证 | 字节内部百万级节点 |
| 借鉴点 | 插件架构设计、eBPF 数据采集方式、Go Agent 与内核驱动的协作模式 |

**Elkeid Agent 架构**：
```
Agent (Go)
  ├── Plugin Manager ──► 加载/管理/热更新插件
  ├── Driver Plugin ────► eBPF 内核事件采集 (进程/fork/execve/网络)
  ├── Collector Plugin ─► 用户态数据采集 (文件/注册表/日志)
  ├── Scanner Plugin ───► Yara 规则扫描
  └── Journal Watcher ──► systemd-journal / Windows EventLog
```

### 2.2 Tracee（Aqua Security）⭐ ~4,510

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/aquasecurity/tracee` |
| 语言 | Go (用户态) + eBPF (内核态) |
| 核心亮点 | **纯 eBPF 运行时安全**：Tracee-eBPF (事件采集) + Tracee-Rules (检测引擎)，支持容器/K8s |
| 监控事件类型 | 进程创建/退出、文件访问、网络连接、内存映射、系统调用参数 |
| 检测规则 | 行为签名规则，正则 + 阈值 + 序列匹配 |
| 借鉴点 | **检测规则引擎设计**、eBPF 事件类型定义、行为基线建模 |

**Tracee 事件→检测→输出流程**：
```
eBPF Hook (kprobe/tracepoint) → Event Pipeline → Rules Engine → Detection Alert
                                                      │
                                            ┌─────────┼─────────┐
                                            │ Signature│ Behavior │
                                            │ (签名匹配)│ (行为序列)│
                                            └──────────┴─────────┘
```

### 2.3 Wazuh ⭐ ~11,000+

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/wazuh/wazuh` |
| 语言 | C (Agent/Server) + Python (规则引擎/管理) + JS (Dashboard) |
| 核心亮点 | **最成熟的 HIDS**：FIM (文件完整性监控)、SCA (安全配置评估)、Log Collector、Malware Detection、Active Response |
| 监控能力 | 文件增删改、注册表变更、进程隐藏检测、端口扫描检测、系统日志采集、CIS 基线扫描 |
| 规则引擎 | **XML 解码器 + 规则**：支持正则匹配、频率阈值、关联规则、MITRE ATT&CK 映射 |
| 告警输出 | JSON 格式 → Filebeat → ES / Splunk / Kafka |
| 借鉴点 | **监控项清单**、FIM 实现思路、规则解码器设计、告警标准化格式 |

**Wazuh 监控数据采集矩阵**：
```
┌──────────────┬──────────────────────────────────────┐
│ 监控类别      │ 具体内容                              │
├──────────────┼──────────────────────────────────────┤
│ 文件完整性    │ 文件创建/删除/修改、权限变更、所有者变更│
│ 系统清单      │ 进程列表、开放端口、网络接口、已安装软件│
│ 日志采集      │ syslog/auth.log/audit.log/Windows EventLog│
│ 安全配置评估  │ CIS Benchmark (OS/DB/WebServer)      │
│ 恶意软件检测  │ Rootkit 扫描、隐藏进程/端口/文件检测    │
│ 命令审计      │ 高危命令监控 (whoami/netstat/... )    │
│ 容器安全      │ Docker API 集成、K8s 审计日志          │
└──────────────┴──────────────────────────────────────┘
```

### 2.4 SigmaHQ 规则生态

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/SigmaHQ/sigma` |
| 规则数量 | **3,000+ 社区维护**的检测规则 |
| 格式 | YAML，平台无关的通用检测签名格式 |
| 规则分类 | Generic Detection / Threat Hunting / Emerging Threats / Compliance |
| 覆盖平台 | Windows (Sysmon/Security/ PowerShell)、Linux (auditd/syslog)、macOS、Cloud (AWS/GCP/Azure) |
| 借鉴点 | **直接复用** Sigma 规则格式定义检测逻辑，用 pySigma 将规则转为 Agent 端可执行的查询 |

**Sigma 规则示例**（检测可疑进程创建）：
```yaml
title: Suspicious Process Creation - Netcat
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects execution of netcat with listening or reverse shell flags
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0: nc
    a1|c|startswith: '-l'      # listening mode
    a2|c|contains: '-e'        # execute flag
  condition: selection
falsepositives:
  - Legitimate admin use of netcat
level: high
tags:
  - attack.execution
  - attack.t1059.004
```

### 2.5 osquery / FleetDM

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/osquery/osquery` + `github.com/fleetdm/fleet` |
| 核心思路 | **用 SQL 查询操作系统**：将进程/文件/网络/用户/内核模块等抽象为 SQL 表 |
| 借鉴点 | **监控数据模型设计**：osquery 的 SQL 表 schema 是设计 Agent 采集数据模型的绝佳参考 |

**osquery 核心表**（最常用于安全监控）：
```
processes         — 所有运行进程 (pid/name/path/cmdline/parent)
process_events    — 进程创建事件 (kprobe/auditd)
file_events       — 文件系统事件 (inotify/Fanotify)
socket_events     — 网络 socket 事件
user_events       — 用户登录/切换事件
kernel_modules    — 已加载内核模块
crontab           — 定时任务
listening_ports   — 监听端口
suid_bin          — SUID 二进制文件
```

### 2.6 YAMAGoya（JPCERT/CC）

| 维度 | 要点 |
|------|------|
| 仓库 | `github.com/JPCERTCC/YAMAGoya` |
| 核心亮点 | **ETW + YARA + Sigma 三合一**：Windows 实时主机监控，用户态纯 C# 实现 |
| 监控源 | 进程创建、文件操作、注册表、DNS、网络连接、PowerShell、WMI |
| 规则格式 | Sigma (标准化检测) + YARA (内存扫描) + Custom YAML (关联规则) |
| 借鉴点 | **监控事件源清单**、Sigma 规则在 Agent 端的实时匹配架构 |

---

## 三、参考项目对比总结

| 项目 | Stars | Agent语言 | 最值得借鉴的点 | 适用场景 |
|------|-------|----------|---------------|---------|
| **Elkeid** | 2.1k | Go | **插件架构** — 我们的 Agent 也是 Go，可以直接参考其模块化设计 | eBPF 内核数据采集 |
| **Tracee** | 4.5k | Go+eBPF | **事件 Pipeline + 规则引擎** — 从内核事件到安全告警的完整流水线 | 容器/K8s 运行时安全 |
| **Wazuh** | 11k+ | C+Python | **监控项清单 + FIM+SCA+日志采集** — 最全面的主机监控能力矩阵 | 传统 HIDS 全功能覆盖 |
| **SigmaHQ** | 8.5k | YAML | **3,000+ 现成规则** — 直接复用，减少从零编写规则的工作量 | 跨平台检测规则 |
| **osquery** | 22k+ | C++ | **SQL 数据模型** — 进程/文件/网络/用户等抽象表设计 | 主机信息查询 |
| **YAMAGoya** | ~200 | C# | **ETW+Sigma 实时匹配** — Windows 端点 Agent 端直接跑 Sigma 规则 | Windows 端点监控 |

---

## 四、改造目标：完整链路

```
┌─────────── 第一段：Agent 监控采集 ────────────┐
│                                                │
│  Go Agent 新增 Monitor 子系统                   │
│  ┌──────────┬──────────┬──────────┬─────────┐ │
│  │进程监控   │文件监控   │网络监控   │日志采集 │ │
│  │fork/exec │inotify   │netstat   │syslog   │ │
│  │/proc扫描 │/Fanotify │/proc/net │journald │ │
│  └──────────┴──────────┴──────────┴─────────┘ │
│  ┌──────────┬──────────┬──────────┬─────────┐ │
│  │系统清单   │用户监控   │Rootkit   │容器监控 │ │
│  │rpm/dpkg  │wtmp/last │隐藏进程  │Docker   │ │
│  │内核模块   │sudo日志  │隐藏端口  │K8s API  │ │
│  └──────────┴──────────┴──────────┴─────────┘ │
│                    │                           │
│           ┌────────▼────────┐                  │
│           │  检测规则引擎    │                  │
│           │  Sigma + YARA   │                  │
│           │  实时匹配/定时   │                  │
│           └────────┬────────┘                  │
│                    │                           │
│           生成安全告警 (标准化 JSON)             │
└────────────────────┬──────────────────────────┘
                     │ WebSocket 上报
                     ▼
┌─────────── 第二段：告警研判 ──────────────────┐
│                                                │
│  Kafka topic: agent-alerts                     │
│  HTTP POST /api/v1/events (兼容现有接口)        │
│          │                                     │
│  ┌───────▼────────┐                            │
│  │ AlertConsumer   │ (复用现有 preprocessing)    │
│  │ 脱敏 → IOC提取  │                            │
│  └───────┬────────┘                            │
│          │                                     │
│  ┌───────▼────────┐                            │
│  │ run_pipeline() │ (复用现有 LangGraph)         │
│  │ entry→分流→研判 │                            │
│  │ →汇聚→响应     │                            │
│  └────────────────┘                            │
└────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────── 第三段：自动响应 ──────────────────┐
│                                                │
│  responder 子图 → HITL 审批 → ActionDispatcher │
│  新增响应动作:                                  │
│  · agent_kill_process (远程杀进程)              │
│  · agent_quarantine_file (隔离文件)             │
│  · agent_isolate_host (主机网络隔离)            │
│  · agent_collect_forensic (采集取证数据)        │
└────────────────────────────────────────────────┘
```

---

## 五、详细改造方案

### 5.1 阶段 1：Agent 监控子系统（优先 Linux）

#### 5.1.1 进程监控 `agent/internal/monitor/process.go`

```
监控项：
├── 进程创建事件 (fork/clone/execve)
│   来源: eBPF kprobe (tracepoint/syscalls:sys_enter_execve)
│   或: /proc 轮询 (低资源模式)
│   字段: pid, ppid, exe, cmdline, uid, gid, cwd, start_time
│
├── 可疑进程检测
│   · 非标准路径执行 (/tmp/./dev/shm/)
│   · 敏感命令执行 (nc/ncat/wget/curl 带可疑参数)
│   · 权限提升 (sudo/su/pkexec)
│   · 进程名称伪装 (svchost/sshd 等系统进程名)
│
└── 进程树异常
    · 孤儿进程 (ppid=1 的非 daemon 进程)
    · 隐藏进程 (/proc 与 tasklist 不一致)
```

**实现方式**（两级策略）：

| 模式 | 技术 | 资源消耗 | 适用场景 |
|------|------|---------|---------|
| **深度模式** | eBPF (kprobe/tracepoint + ringbuf) | 低 (~3% CPU) | 生产服务器、核心资产 |
| **轻量模式** | /proc 轮询 (1-5s 间隔) | 极低 (<1% CPU) | 低配主机、非核心资产 |

**eBPF 方案参考 Elkeid/Tracee**：
- 使用 `cilium/ebpf` 纯 Go 库加载 eBPF 字节码
- 挂载 `tracepoint/syscalls/sys_enter_execve` 和 `sys_exit_execve`
- 通过 ring buffer 将内核事件投递到 Go 用户态
- Go 侧进行事件解析、富化（补充 uid→username 映射等）

#### 5.1.2 文件完整性监控 `agent/internal/monitor/file.go`

```
监控项：
├── 文件操作事件
│   来源: inotify (Linux) / FSEvents (macOS) / ReadDirectoryChangesW (Windows)
│   字段: path, event_type(create/delete/modify/rename/chmod/chown), timestamp
│
├── 关键目录监控（可配置白名单）
│   · /etc/passwd, /etc/shadow, /etc/sudoers
│   · /etc/crontab, /var/spool/cron/
│   · /etc/systemd/system/
│   · ~/.ssh/authorized_keys
│   · /usr/bin/, /usr/sbin/ (二进制替换)
│
├── SUID/SGID 变更检测
│   · 定期扫描所有 SUID 二进制，对比基线
│
└── WebShell 检测
    · 监控 Web 目录新增 .php/.jsp/.aspx 文件
    · 文件内容特征扫描（eval/base64_decode 等）
```

**参考 Wazuh FIM 实现**：
- 配置监控目录白名单/黑名单
- 文件 hash (SHA256) 变更即告警
- 支持 `whodata` 模式（记录是哪个用户改的）

#### 5.1.3 网络连接监控 `agent/internal/monitor/network.go`

```
监控项：
├── 监听端口变更
│   来源: /proc/net/tcp, /proc/net/tcp6 (定期轮询)
│   字段: local_ip, local_port, process_name, pid
│   检测: 新增监听端口、非标准端口
│
├── 外连检测
│   来源: /proc/net/tcp + /proc/<pid>/fd
│   检测:
│   · 已知恶意 IP/域名（对接威胁情报）
│   · 非业务时段的外连
│   · 敏感端口外连 (22/3389/1433/3306/6379 出站)
│
├── DNS 查询监控
│   来源: eBPF (uprobe:libc getaddrinfo) 或 auditd
│   检测: DGA 域名、DNS 隧道、异常 TLD
│
└── 网络流量异常
    · 单进程大流量 (数据外传)
    · ICMP 隧道 (大包)
```

#### 5.1.4 日志采集 `agent/internal/monitor/log.go`

```
监控项：
├── 系统认证日志
│   来源: /var/log/auth.log (Debian) / /var/log/secure (RHEL)
│   检测: SSH 爆破、sudo 失败、异常登录时间/IP
│
├── 系统日志
│   来源: /var/log/syslog / /var/log/messages
│   检测: kernel panic、OOM、服务崩溃
│
├── 审计日志
│   来源: auditd (/var/log/audit/audit.log)
│   检测: 敏感系统调用、SELinux AVC 拒绝
│
└── 应用日志
│   来源: 可配置路径 (nginx/redis/mysql/tomcat...)
│   检测: SQL 注入、路径穿越、命令注入
```

#### 5.1.5 系统清单采集 `agent/internal/monitor/inventory.go`

```
监控项：
├── 软件清单    rpm -qa / dpkg -l → 对比 CVE 数据库
├── 内核模块    lsmod → 检测可疑/隐藏模块
├── 启动项      systemctl list-unit-files / crontab / rc.local
├── 用户账户    /etc/passwd → 新增用户/uid=0检测
├── SSH 配置    /etc/ssh/sshd_config → PermitRootLogin/PasswordAuthentication
└── 计划任务    crontab 所有用户 → 异常时间/异常命令
```

### 5.2 阶段 2：检测规则引擎

#### 5.2.1 规则格式：直接复用 Sigma

```
理由:
1. 3,000+ 现成社区规则，不需要从零写
2. YAML 格式，与现有 playbook YAML 风格一致
3. pySigma 生态完善，可自动转换为 Agent 查询
4. 支持 MITRE ATT&CK 映射
```

**Agent 端 Sigma 规则匹配流程**：
```
Sigma YAML 规则 ──► pySigma 编译 ──► Agent 规则包 (JSON)
                                         │
                              ┌──────────▼──────────┐
                              │  Agent 规则引擎       │
                              │  · 字段匹配           │
                              │  · 正则/通配符        │
                              │  · 频率阈值           │
                              │  · 序列关联 (stateful)│
                              │  · 时间窗口            │
                              └──────────┬──────────┘
                                         │
                                    命中 → 生成告警
```

**示例：将 Sigma 规则转为 Agent 规则 JSON**：
```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "title": "Suspicious Netcat Execution",
  "level": "high",
  "mitre": ["TA0002", "T1059.004"],
  "conditions": {
    "event_type": "process_create",
    "fields": {
      "exe": {"endswith": "/nc"},
      "cmdline": {"regex": "(-[eE]\\s+/bin/(ba)?sh|-l\\s+-p\\s+\\d+)"}
    }
  }
}
```

#### 5.2.2 规则获取渠道

| 来源 | 数量 | 获取方式 |
|------|------|---------|
| SigmaHQ 官方仓库 | 3,000+ | `git clone` → 筛选 Linux/通用规则 → pySigma 编译 |
| 自研规则 (SecAgent) | 初始 ~50 条 | YAML → 编译为 Agent 规则包 |
| Wazuh 规则库 | 1,000+ | 参考其 XML 规则逻辑，转为 Sigma → Agent 规则 |
| 社区贡献 | 长期 | 提供规则编写指南，接受 PR |

#### 5.2.3 规则热更新（复用现有机制）

```
服务端: rules_sync.py 扩展
  ├── CVE 规则 (现有)
  ├── Sigma 检测规则 (新增)
  └── YARA 规则 (新增)
       │
       ▼
  Ed25519 签名 → WS 下发 rule_update → Agent 热加载
```

### 5.3 阶段 3：告警生成与上报

#### 5.3.1 标准化告警格式

```json
{
  "alert_id": "uuid",
  "agent_id": "agent-xxx",
  "hostname": "web-server-01",
  "timestamp": "2026-07-26T10:30:00Z",
  "rule_id": "sigma-process-001",
  "rule_name": "Suspicious Netcat Execution",
  "level": "high",
  "category": "process_create",
  "mitre_attack": ["TA0002", "T1059.004"],
  "source": "secagent-monitor",
  "event": {
    "type": "process_create",
    "pid": 12345,
    "ppid": 1234,
    "uid": 0,
    "username": "root",
    "exe": "/usr/bin/nc",
    "cmdline": "nc -l -p 4444 -e /bin/bash",
    "cwd": "/tmp",
    "parent_exe": "/bin/bash",
    "parent_cmdline": "-bash"
  },
  "context": {
    "container_id": null,
    "pod_name": null,
    "risk_score": 85
  }
}
```

#### 5.3.2 上报方式（两种策略）

```
策略 A：实时上报 (高优先级告警)
  Agent 检测到 CRITICAL/HIGH → 立即 WebSocket send → WS Gateway → run_pipeline()

策略 B：批量上报 (低优先级/信息类)
  Agent 缓冲 N 条或 M 秒 → 批量 push → Kafka topic: agent-alerts
```

**复用现有 WS 消息通道**：新增 `alert` 消息类型：
```go
// agent/internal/comm/client.go 新增
func (c *Client) SendAlert(alert Alert) {
    c.send(map[string]interface{}{
        "v":       1,
        "type":    "alert",          // 新消息类型
        "ts":      time.Now().UTC().Format(time.RFC3339),
        "payload": alert,
    })
}
```

**服务端 WS Gateway 接收**：
```python
# src/agents/ws_gateway.py 新增消息处理
elif msg["type"] == "alert":
    alert_data = msg["payload"]
    # 1. 写入 ES (告警存储)
    # 2. 判断优先级
    # 3. HIGH/CRITICAL → 同步调用 run_pipeline()
    # 4. MEDIUM/LOW → 写入 Kafka topic (异步)
```

### 5.4 阶段 4：第三方 EDR/告警接入

#### 5.4.1 支持的接入方式

```
┌─────────────────────────────────────────────────┐
│              第三方告警源                          │
├─────────────┬──────────┬────────────┬───────────┤
│  Wazuh      │ Elkeid   │ Elastic    │ 商业 EDR  │
│  Agent      │ Agent    │ Agent      │ CrowdStrike│
│  (syslog)   │ (Kafka)  │ (ES/Kafka) │  SentinelOne│
├─────────────┴──────────┴────────────┴───────────┤
│              │                                   │
│    ┌─────────┼─────────┬───────────┐            │
│    ▼         ▼         ▼           ▼            │
│  Syslog   Kafka     HTTP API   Webhook          │
│  (UDP514) (9092)   /events    /webhook/edr      │
└────────────┬────────────────────────────────────┘
             │
    ┌────────▼──────────────────────┐
    │  告警标准化适配层 (新增)        │
    │  EDR Alert Normalizer          │
    │                                │
    │  Wazuh JSON → SecAgent Event   │
    │  Elastic Alert → SecAgent Event│
    │  CrowdStrike → SecAgent Event  │
    │  Syslog → SecAgent Event       │
    └────────┬──────────────────────┘
             │
    ┌────────▼──────────────────────┐
    │  run_pipeline() (复用现有)     │
    │  entry → 分流 → 研判 → 响应    │
    └───────────────────────────────┘
```

#### 5.4.2 告警标准化适配器

```python
# src/preprocessing/edr_adapter/__init__.py (新增模块)

class EDRAlertNormalizer:
    """将不同 EDR 的告警格式统一为 SecAgent Event 格式"""

    ADAPTERS = {
        "wazuh": WazuhAdapter,
        "elastic": ElasticAdapter,
        "elkeid": ElkeidAdapter,
        "crowdstrike": CrowdStrikeAdapter,
        "sentinelone": SentinelOneAdapter,
        "syslog": SyslogAdapter,
        "secagent": SecAgentAdapter,  # 我们自己的 Agent
    }

    def normalize(self, raw_alert: dict, source: str) -> dict:
        adapter = self.ADAPTERS[source]()
        return {
            "event_id": adapter.extract_id(raw_alert),
            "sanitized_text": adapter.to_text(raw_alert),
            "iocs": adapter.extract_iocs(raw_alert),
            "source": source,
            "original": raw_alert,  # 保留原始数据
            "mitre_attack": adapter.extract_mitre(raw_alert),
            "priority": adapter.map_priority(raw_alert),
        }
```

**每种 EDR 适配器实现**：
```python
# 示例：Wazuh 适配器
class WazuhAdapter:
    def extract_id(self, alert):
        return alert.get("id", str(uuid.uuid4()))

    def to_text(self, alert):
        rule = alert.get("rule", {})
        return f"Wazuh: {rule.get('description')} on {alert.get('agent',{}).get('name')}"

    def extract_iocs(self, alert):
        data = alert.get("data", {})
        return {
            "ips": [data.get("srcip"), data.get("dstip")],
            "domains": [],
            "hashes": [data.get("md5"), data.get("sha256")],
            "urls": [],
        }

    def extract_mitre(self, alert):
        return alert.get("rule", {}).get("mitre", {}).get("id", [])

    def map_priority(self, alert):
        level = alert.get("rule", {}).get("level", 5)
        if level >= 12: return "critical"
        if level >= 10: return "high"
        if level >= 7:  return "medium"
        return "low"
```

### 5.5 阶段 5：新增响应动作

Agent 监控到威胁后，除了服务端研判→审批→执行现有动作，还需 Agent 端能**执行响应指令**：

```
现有 WS 指令:
  scan_command / scan_cancel / rule_update / agent_upgrade / config_update

新增 WS 指令:
  ├── kill_process     "终止指定 PID 的进程"
  ├── quarantine_file  "隔离文件 (移动到隔离目录 + chmod 000)"
  ├── block_ip         "iptables/nftables 临时封禁 IP"
  ├── collect_memory   "采集进程内存 dump (取证)"
  ├── collect_file     "采集指定文件 (取证回传)"
  └── isolate_host     "主机网络隔离 (iptables DROP all except WS)"
```

**Go Agent 侧实现**：
```go
// agent/internal/monitor/responder.go (新增)

func HandleKillProcess(pid int) error {
    process, err := os.FindProcess(pid)
    if err != nil { return err }
    return process.Signal(syscall.SIGKILL)
}

func HandleQuarantineFile(path string) error {
    quarantineDir := "/opt/secagent/quarantine/"
    // 1. 计算文件 hash (取证记录)
    // 2. move → quarantineDir
    // 3. chmod 000
    // 4. 上报操作结果
}

func HandleBlockIP(ip string, duration time.Duration) error {
    // iptables -A INPUT -s <ip> -j DROP
    // 启动 goroutine 在 duration 后自动清理规则
}

func HandleIsolateHost(allowedIPs []string) error {
    // iptables -P INPUT DROP
    // iptables -P OUTPUT DROP
    // iptables -A INPUT -s <console_ip> -j ACCEPT  (保证 WS 不断)
    // iptables -A OUTPUT -d <console_ip> -j ACCEPT
}
```

### 5.6 阶段 6：新增 playbook（Agent 监控场景）

```yaml
# src/orchestration/playbooks/process_injection.yaml (新增)
playbook_id: process_injection
description: "可疑进程注入 → 取证采集 → 终止进程 → 主机扫描"
trigger:
  verdict: true_positive
  event_tags: ["process_injection", "ptrace", "code_injection"]
  confidence_min: 0.8
max_level: L3
operations:
  - type: agent_collect_memory
    level: L1
    params:
      pid: '{pid}'
  - type: agent_kill_process
    level: L2
    params:
      pid: '{pid}'
  - type: agent_quarantine_file
    level: L2
    params:
      path: '{exe_path}'
  - type: vuln_scan
    level: L3
    params:
      target: '{hostname}'
      modules: [sys_vuln, baseline]
  - type: notify
    level: L1
    params:
      channel: security_team
```

---

## 六、Agent 内部新增模块总览

```
agent/
├── internal/
│   ├── comm/               (现有)
│   │   └── client.go       [修改] 新增 SendAlert(), 新增 alert/respond 消息处理
│   ├── monitor/            (★ 新增模块)
│   │   ├── manager.go      # MonitorManager: 管理所有采集器生命周期
│   │   ├── process.go      # 进程监控 (eBPF或/proc轮询)
│   │   ├── file.go         # 文件完整性监控 (inotify)
│   │   ├── network.go      # 网络连接监控 (/proc/net)
│   │   ├── log.go          # 日志采集 (tail -f)
│   │   ├── inventory.go    # 系统清单采集
│   │   ├── rootkit.go      # Rootkit 检测 (隐藏进程/端口/文件)
│   │   ├── detector.go     # 检测引擎: Sigma 规则实时匹配
│   │   ├── responder.go    # 响应执行: kill/quarantine/block/isolate
│   │   ├── alert.go        # 告警生成器: 事件 → 标准化 JSON
│   │   └── rules/          # 内嵌 Sigma 规则包 (编译后 JSON)
│   │       └── default.json
│   ├── ebpf/               (★ 新增, 可选编译)
│   │   ├── tracer.go       # eBPF 加载器 (cilium/ebpf)
│   │   └── bpf/            # eBPF C 源码
│   │       ├── execve.c
│   │       └── network.c
│   └── ...                 (现有模块不变)
```

---

## 七、服务端新增模块

```
src/
├── preprocessing/
│   ├── consumer.py          (现有, 不需改)
│   ├── edr_adapter/         (★ 新增)
│   │   ├── __init__.py      # EDRAlertNormalizer + 路由
│   │   ├── wazuh.py         # Wazuh → SecAgent 适配
│   │   ├── elastic.py       # Elastic Alert → SecAgent
│   │   ├── elkeid.py        # Elkeid → SecAgent
│   │   ├── crowdstrike.py   # CrowdStrike → SecAgent
│   │   ├── syslog.py        # Syslog → SecAgent
│   │   └── secagent.py      # 我们自己的 Agent → SecAgent
│   └── webhook_receiver.py  (★ 新增) EDR Webhook 接收端点
│
├── orchestration/
│   ├── playbooks/           (新增 playbook)
│   │   ├── process_injection.yaml
│   │   ├── webshell_detect.yaml
│   │   ├── data_exfil.yaml
│   │   ├── privilege_escalation.yaml
│   │   └── suspicious_network.yaml
│   └── subgraphs/
│       └── responder/
│           └── agent_actions.py  (★ 新增) Agent 远程指令下发
│
├── api/routers/
│   └── webhooks.py          (★ 新增) /api/v1/webhooks/edr/{vendor}
│
└── agents/
    ├── ws_gateway.py        [修改] 新增 alert 消息类型处理
    └── rules_sync.py        [修改] 新增 Sigma 规则编译+分发
```

---

## 八、实施路线图

### 第一批：基础监控（4-6 周）

| 任务 | 估时 | 产出 |
|------|------|------|
| Agent: 进程监控 (/proc 轻量模式) | 3d | `monitor/process.go` |
| Agent: 文件完整性监控 (inotify) | 3d | `monitor/file.go` |
| Agent: 网络连接监控 | 2d | `monitor/network.go` |
| Agent: MonitorManager 生命周期管理 | 2d | `monitor/manager.go` |
| Agent: 告警生成 + WS 上报 (alert 消息类型) | 2d | `alert.go` + `client.go` 修改 |
| 服务端: WS Gateway 接收 alert 消息 | 2d | `ws_gateway.py` 修改 |
| 服务端: 告警→run_pipeline() 集成 | 2d | consumer 集成 |
| 单元测试 | 4d | monitor/*_test.go + API 测试 |
| **小计** | **20d** | Agent 基础监控 + 告警上报闭环 |

### 第二批：检测规则引擎（3-4 周）

| 任务 | 估时 | 产出 |
|------|------|------|
| Agent: 规则引擎 (字段匹配+正则+频率) | 5d | `monitor/detector.go` |
| 从 SigmaHQ 筛选 Linux 规则 (~500条) | 2d | 规则筛选 + 适配 |
| pySigma → Agent 规则包编译工具 | 3d | `scripts/compile_sigma_rules.py` |
| Agent: 规则热加载 (复用现有 rule_update) | 2d | 与 updater 集成 |
| 服务端: rules_sync.py 扩展 Sigma 规则 | 2d | `rules_sync.py` 修改 |
| 单元测试 | 3d | detector_test.go + 规则编译测试 |
| **小计** | **17d** | 500+ 检测规则上线 |

### 第三批：第三方 EDR 接入（2-3 周）

| 任务 | 估时 | 产出 |
|------|------|------|
| EDR Alert Normalizer 框架 | 2d | `edr_adapter/__init__.py` |
| Wazuh 适配器 | 2d | `edr_adapter/wazuh.py` |
| Elastic Agent 适配器 | 2d | `edr_adapter/elastic.py` |
| Syslog 接收器 (UDP 514) | 2d | `webhook_receiver.py` |
| Webhook 接收端点 | 2d | `api/routers/webhooks.py` |
| 单元测试 | 3d | 各适配器测试 |
| **小计** | **13d** | 3 种 EDR 接入 |

### 第四批：Agent 响应动作 + 新 playbook（2-3 周）

| 任务 | 估时 | 产出 |
|------|------|------|
| Agent: kill_process / quarantine_file | 2d | `monitor/responder.go` |
| Agent: block_ip / isolate_host | 2d | `monitor/responder.go` |
| 服务端: Agent 远程指令下发 | 2d | `agent_actions.py` |
| 新增 5 个监控场景 playbook | 2d | YAML playbook |
| 集成测试 (端到端) | 4d | E2E 测试场景 |
| **小计** | **12d** | 完整响应闭环 |

### 第五批：深度监控 + eBPF（4-6 周，可选）

| 任务 | 估时 | 产出 |
|------|------|------|
| eBPF 进程事件采集 | 5d | `ebpf/tracer.go` + bpf C 代码 |
| eBPF 网络事件采集 | 3d | DNS/connect hook |
| 容器/K8s 感知 | 3d | cgroup 关联 + k8s 元数据 |
| 内存扫描 (YARA) | 3d | 集成 YARA 规则 |
| 性能调优 + 压测 | 5d | benchmark |
| **小计** | **19d** | 深度监控 + 容器支持 |

---

## 九、优先级矩阵

```
                    高价值
                      │
        ★ 进程监控     │     ★ Sigma规则引擎
        ★ 文件完整性   │     ★ 告警→研判集成
        ★ 网络监控     │     ★ EDR适配器
                      │
    ──────────────────┼──────────────────
        容易          │          困难
                      │
        ★ 日志采集     │     ★ eBPF深度监控
        ★ 系统清单     │     ★ YARA内存扫描
        ★ Webhook接收  │     ★ 容器安全
                      │
                    低价值
```

**第一批（最容易+最高价值）立即启动**：进程监控 + 文件完整性 + 网络监控 + 告警上报。

---

## 十、风险与注意事项

| 风险 | 应对 |
|------|------|
| eBPF 内核版本兼容性 | 提供 /proc 轮询降级模式，eBPF 编译为可选特性 |
| 监控性能开销 | 默认轻量模式（/proc），深度模式 (eBPF) 需用户手动开启 |
| Sigma 规则误报 | 先导入 stable 状态的规则，提供白名单机制 |
| 第三方 EDR 格式差异大 | 适配器模式逐个适配，保留原始数据 |
| Agent 体积膨胀 | 监控模块编译为可选 feature flag，按需启用 |
| Windows 兼容性 | 首批只支持 Linux，Windows 单独规划 |

---

## 十一、总结：改造前后对比

| 维度 | 改造前 | 改造后 |
|------|--------|--------|
| Agent 角色 | 被动扫描器（只响应 scan_command） | **主动监控 + 被动扫描** 双角色 |
| 数据采集 | CPU/内存粗略采样 | **进程+文件+网络+日志+清单** 全方位 |
| 检测能力 | 仅 CVE 漏洞匹配 | **CVE漏洞 + Sigma行为检测 + YARA内存扫描** |
| 告警来源 | 外部 Kafka/HTTP 推送 | **Agent 主动上报 + 外部 Kafka/HTTP + 第三方 EDR Webhook** |
| 规则数量 | ~100 条 CVE 规则 | **500+ Sigma 行为规则 + 100 条 CVE 规则** |
| 响应动作 | notify/siem_tag/dns_block/simulator | **+ agent_kill_process / agent_quarantine_file / agent_block_ip / agent_isolate_host / agent_collect_forensic** |
| 完整链路 | ❌ 缺失第一段 | ✅ Agent监控→告警上报→研判→响应，全线贯通 |
| 第三方集成 | 无 | **Wazuh + Elastic + CrowdStrike + Syslog** |
