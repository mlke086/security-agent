# 演示截图说明

| 文件 | 对应模块 | 内容 |
|---|---|---|
| 00-login.png | 模块 1 | 登录页(账号提示 + 主题色块) |
| 00-after-login.png | 模块 2 | 登录后的 Dashboard(管理员视角) |
| 01-dashboard.png | 模块 2 | 态势感知 — 4 张统计卡 + 2 张条形图 + 时间线 |
| 02-events.png | 模块 3 | 事件队列(7 条样例事件) |
| 02b-event-detail.png | 模块 3 | 事件推理链时间线 |
| 03-approvals.png | 模块 4 | 待审批列表 |
| 04-hosts.png | 模块 5 | 主机纳管 + Agent 注册 |
| 05-scan-tasks.png | 模块 6 / 7 | 扫描任务列表(89 条历史) |
| 05b-scan-chat.png | 模块 6 / 11 | 对话式扫描 + AI 助手 |
| 06-vulns.png | 模块 8 | 漏洞清单(CVE + 基线) |
| 07-report.png | 模块 8 | 扫描报告查询入口 |
| 07b-report-detail.png | 模块 8 | 完整扫描报告(AI 摘要 + 严重等级分布 + Top 漏洞) |
| 08-rules.png | 模块 9 | 规则管理(NVD 同步 + Ed25519 下发) |
| 09-models.png | 模块 10 | 模型管理(多 LLM 切换) |

## 重新生成

```bash
# 1) 确认前端 dev server 运行(localhost:3000)、后端 (localhost:8000)
# 2) 执行截图脚本(在 .venv 下,需先 pip install playwright)
python V:\project\security-agent\scripts\_demo_screenshots.py
python V:\project\security-agent\scripts\_demo_screenshots_extra.py
```
