"""S0-5: Deployment decision record.

Based on 服务快速调用表.md & 计划v1.md Section 6.

1. MinIO
   - Role: Milvus底层对象存储。Milvus 2.4 默认使用 MinIO 做向量数据持久化。
   - Impact: 应用代码无需直连 MinIO。pymilvus 客户端通过 Milvus 服务端自动使用。
   - Action: 无需在 settings.py 中添加 MinIO 配置。运维端已部署即可。

2. ClickHouse
   - Role: 运营指标/事件分析列式存储。替代或补充 ES 做审计聚合和Dashboard查询。
   - Impact: 如果引入，需要:
     a) 新增 clickhouse-connect 依赖
     b) settings.py 增加 CLICKHOUSE_HOST/PORT/DB 配置
     c) audit_logger 和 dashboard 端点需适配双写或切换
   - Decision (prototype): 暂不使用。ES 已满足原型阶段需求。Sprint 3 仪表盘阶段再评估。

3. Nacos
   - Role: 配置中心/服务注册。可用于动态下发 settings 和规则热更新。
   - Impact: 如果引入，需要:
     a) 新增 nacos-sdk-python 依赖
     b) 实现 ConfigListener 将 Nacos 配置同步到 Pydantic Settings
     c) 重构 get_settings() 为支持热加载
   - Decision (prototype): 暂不使用。原型阶段用 .env + Pydantic Settings 即可。
     Sprint 4 生产加固阶段再评估。
'''
# Just documentation - no code execution needed
print("S0-5: Decision items documented")
