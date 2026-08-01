"""V12 阶段 4.2: SSE 路由顺序回归测试。

2026-07-28 e2e sweep 发现 ``GET /api/v1/events/stream`` 被
``GET /api/v1/events/{event_id}/stream`` 遮蔽（FastAPI 按注册顺序匹配，
``{event_id}`` 抢走 "stream" 字符串当 event_id），EventQueuePage 的
EventSource 一直 404。代码在 stream.py 中已修（字面路由在参数路由之前注册），
但此前无回归测试 —— 本文件锁定该行为，防止未来重排路由再次遮蔽。
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def test_events_stream_not_masked_by_event_id_stream(auth_headers):
    """/events/stream 必须路由到 events_list_stream（200），而非被
    /events/{event_id}/stream 吃掉返回 404。"""
    token = auth_headers("analyst")["Authorization"].split(" ")[-1]
    from src.api.auth.sse_tokens import mint_sse_token

    sse = mint_sse_token(token, "events_list")

    async def fake_gen(*args, **kwargs):
        yield "data: x\n\n"

    with patch("src.api.routers.stream._sse_generator", side_effect=fake_gen):
        resp = client.get("/api/v1/events/stream", params={"token": sse})
    # 200 (stream) -- NOT 404 "Event not found" with event_id="stream"
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("content-type", "").startswith("text/event-stream")


def test_event_id_stream_still_works_for_real_ids(auth_headers):
    """带真实 event_id 的流端点不受影响。"""
    token = auth_headers("analyst")["Authorization"].split(" ")[-1]
    from src.api.auth.sse_tokens import mint_sse_token

    sse = mint_sse_token(token, "events")

    async def fake_gen(*args, **kwargs):
        yield "data: x\n\n"

    with patch("src.api.routers.stream._sse_generator", side_effect=fake_gen):
        resp = client.get("/api/v1/events/evt-123/stream", params={"token": sse})
    assert resp.status_code == 200, resp.text


def test_events_stream_rejects_wrong_scope(auth_headers):
    """events_list scope token 用于 events/{id}/stream 必须 403（scope 隔离）。"""
    token = auth_headers("analyst")["Authorization"].split(" ")[-1]
    from src.api.auth.sse_tokens import mint_sse_token

    sse = mint_sse_token(token, "events_list")
    resp = client.get("/api/v1/events/evt-123/stream", params={"token": sse})
    assert resp.status_code == 401, resp.text
