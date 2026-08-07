"""阶段 4-2:事件入队 stream 共享常量。

scan-engine 端消费者与 preprocessing 端生产者必须读同一份常量,
确保 stream 名一致。常量值与方案 4.2 节 ``events:tasks`` 对齐。

跨服务契约:
- preprocessing 镜像 COPY 本目录,调 ``enqueue_event(event_id, payload)`` 推入 EVENT_STREAM
- scan-engine 镜像 COPY 本目录(同一份),启动 consumer loop 监听 EVENT_STREAM
"""

# 阶段 4-2:EDR 事件入队 stream(与 vulnscan:tasks 任务流分离)
EVENT_STREAM = "events:tasks"

# EDR 事件消费组(scan-engine 镜像启动时 XGROUP CREATE MKSTREAM)
EVENT_CONSUMER_GROUP = "scan-engine-events"

# EDR 事件消费者名(scan-engine 启动时生成 unique consumer name,
# 多副本场景下保证每个 worker 单独 ack)
EVENT_CONSUMER_NAME_PREFIX = "scan-engine-events-"
