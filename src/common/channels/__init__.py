"""阶段 5 收尾 P0-3:Redis Pub/Sub channel 共享常量。

scan-engine 写入端与 gateway 读取端必须读同一份常量,
确保 channel 名一致(隐式契约文档化)。

现状(之前散落 3 处):
- src/orchestration/subgraphs/vulnscan/nodes.py:1008 scan-engine publish
- src/api/routers/vulnscan.py:372 / 413 / 490 gateway SSE 订阅

后续若有新增 scan-engine↔gateway pub/sub 链路,加在本文件,
避免再写裸 channel 字符串。
"""


def vulnscan_task_channel(task_id: str) -> str:
    """vulnscan 任务进度 channel(``vulnscan:task:{task_id}``)。

    scan-engine 端 ``_pub_progress`` publish,gateway ``api_task_stream`` SSE 订阅。
    """
    return f"vulnscan:task:{task_id}"
