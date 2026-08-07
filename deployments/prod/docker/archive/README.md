# Archive:单体时代部署文件

阶段 5 收尾:这些文件属于单体 `secagent-api:0.1.0` 镜像时代,
已被新文件取代,留档供回滚参考,**不应再被 compose 或文档引用**。

> 注:同名 .deprecated 文件(若需要查阅)请用 git 历史或备份归档恢复。
> 本目录仅保留本 README 作为占位说明。

## 新文件映射

| 旧文件 | 替代者 |
|--------|--------|
| `Dockerfile.api` | `Dockerfile.gateway` + `Dockerfile.ai` + `Dockerfile.scan-engine` + `Dockerfile.graphrag` + `Dockerfile.preprocessing` + `Dockerfile.celery` |
| `entrypoint.sh` | `entrypoint-gateway.sh` + `entrypoint-ai.sh` + `entrypoint-scan-engine.sh` + `entrypoint-graphrag.sh` + `entrypoint-celery.sh` |
| `run_taskworker.py` | `src/scan_engine/main.py` 的 lifespan(uvicorn 启动时自动启动 TaskWorker) |
| `nacos-config.yaml` | `nacos/{shared,gateway,ai,scan-engine,graphrag,celery,preprocessing}.yaml` 7 个 dataId |

## 回滚剧本(若新拆分方案线上故障)

1. `docker tag secagent-gateway:0.1.0 secagent-gateway:prev`(每阶段起动前已打 tag)
2. 旧 `docker-compose.yml` 归档为 `../docker-compose.legacy.yml`,需要时 `cp` 回去
3. Nacos 旧 dataId `security-agent.yaml` 保留 7 天
4. `docker compose -f docker-compose.yml up -d --force-recreate secagent-api:0.1.0`

## 永久清理

7 天后无故障,可删除本目录与 `../docker-compose.legacy.yml`。