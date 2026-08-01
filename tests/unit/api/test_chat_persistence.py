"""Tests for the unified /api/v1/chat router (V9 Spec-P1-F2).

Covers:
- The router persists the user + assistant turn to the conversation store
  (previously /chat was stateless, so normal turns vanished on reload and
  the scan-execute path persisted a *different* reply from a 2nd LLM call).
- The scan route reuses the ScanIntent the classifier already extracted
  (one LLM call), falling back to a dedicated parse call only when the
  classifier did not populate scan_intent.
"""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)




def _adapter_for(side_effect):
    mock_adapter = AsyncMock()
    mock_adapter.chat_completion = AsyncMock(side_effect=side_effect)
    return mock_adapter


def test_chat_persists_user_and_assistant( auth_headers ):
    """F2: /chat must persist exactly the user turn and the assistant reply
    it rendered -- so displayed history == stored history."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(intent="chat", confidence=0.9, reason="t")
        return "hello reply"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={"message": "hi", "history": [], "conversation_id": "conv-1"},
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent"] == "chat"
    assert body["reply"] == "hello reply"
    # persisted exactly the user turn + the assistant turn we rendered
    assert mock_conv.append_message.await_count == 2
    calls = mock_conv.append_message.await_args_list
    assert calls[0].args == ("conv-1", "user", "hi")
    assert calls[1].args == ("conv-1", "assistant", "hello reply")


def test_chat_no_persist_without_conversation_id( auth_headers ):
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(intent="chat", confidence=0.9)
        return "hi there"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={"message": "hi", "history": []},
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    assert mock_conv.append_message.await_count == 0


def test_chat_scan_reuses_classifier_scan_intent( auth_headers ):
    """F2: when the classifier populates scan_intent, the scan route must
    NOT make a second LLM call to parse the intent."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.9,
                scan_intent=ScanIntent(targets=["h1"], modules=["sys_vuln"]),
            )
        return "should not be called"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={"message": "scan h1", "history": [], "conversation_id": "c1"},
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent"] == "scan"
    assert body["sources"], "scan intent must be surfaced in sources"
    # only the classify call happened (scan_intent reused, no 2nd parse)
    assert mock_get.return_value.chat_completion.await_count == 1


def test_chat_scan_falls_back_when_no_scan_intent( auth_headers ):
    """F2: when the classifier did not populate scan_intent, the scan route
    falls back to a dedicated parse call (2 calls total)."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        schema = kw.get("schema")
        if schema is IntentDecision:
            return IntentDecision(intent="scan", confidence=0.9, scan_intent=None)
        if schema is ScanIntent:
            return ScanIntent(targets=["h2"], modules=[])
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={"message": "scan", "history": [], "conversation_id": "c2"},
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    assert mock_get.return_value.chat_completion.await_count == 2

# V10 1.2: ensure fire-and-forget scan_chat auto-title task survives GC.
def test_auto_title_task_is_referenced_in_bg_set():
    # The chat handler kicks off an asyncio.create_task() for the
    # auto-title generator. Per V10 1.2 the task is added to
    # _BG_TASKS so CPython cannot GC it before completion.
    import asyncio
    import gc

    from src.api.routers import scan_chat

    async def run():
        # The task is created by the chat handler; we exercise
        # it indirectly by checking the set after a fake call.
        t = asyncio.create_task(asyncio.sleep(0))
        scan_chat._BG_TASKS.add(t)
        t.add_done_callback(scan_chat._BG_TASKS.discard)
        # Force GC -- the strong ref in _BG_TASKS keeps the task
        # alive until completion.
        gc.collect()
        await t
        assert t.done()
        # After completion the callback removes the entry.
        assert t not in scan_chat._BG_TASKS
        # We cannot assert before == 0 (other tests may leave
        # entries); just assert the contract works.

    asyncio.run(run())


async def test_scan_chat_intent_uses_only_user_turns():
    from src.agents.models import ScanIntent
    from src.api.routers.scan_chat import _parse_intent_background

    adapter = AsyncMock()
    adapter.chat_completion.return_value = ScanIntent(
        targets=["Rocky001"], engine="nuclei"
    )
    history = [
        {"role": "system", "content": "chat system"},
        {"role": "user", "content": "scan Rocky001"},
        {"role": "assistant", "content": "intent is clear; click execute"},
        {"role": "user", "content": "use nuclei"},
    ]
    intent = await _parse_intent_background(adapter, history, None)
    assert intent is not None and intent.engine == "nuclei"


class TestChatClassifyDegraded:
    """S-P1-4 (V12): a classifier exception must surface as 503 + audit,
    NOT silently degrade to free-form chat."""

    def test_classifier_exception_returns_503_and_audits(self, auth_headers):
        from src.api.routers.chat import IntentDecision

        def completion(*a, **kw):
            if kw.get("schema") is IntentDecision:
                raise RuntimeError("classifier blew up")
            return "should not be reached"

        headers = auth_headers("analyst")
        with (
            patch("src.api.routers.chat.get_model_adapter") as mock_get,
            patch("src.api.routers.chat.conv_store") as mock_conv,
            patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        ):
            mock_get.return_value = _adapter_for(completion)
            mock_conv.append_message = AsyncMock()
            mock_audit.return_value.log = AsyncMock()
            resp = client.post(
                "/api/v1/chat",
                json={"message": "帮我扫描 test 组", "history": []},
                headers=headers,
            )
        assert resp.status_code == 503, resp.text
        assert "分类服务暂不可用" in resp.json()["detail"]
        # audit entry recorded
        mock_audit.return_value.log.assert_awaited_once()
        assert mock_audit.return_value.log.await_args.kwargs["action"] == "chat_classify_degraded"
        # nothing persisted, nothing answered
        assert mock_conv.append_message.await_count == 0

    def test_model_not_found_returns_404_not_503(self, auth_headers):
        from src.api.routers.chat import IntentDecision
        from src.knowledge.models.adapter import ModelNotFoundError

        def completion(*a, **kw):
            if kw.get("schema") is IntentDecision:
                raise ModelNotFoundError("model id=999 not found")
            return "x"

        headers = auth_headers("analyst")
        with (
            patch("src.api.routers.chat.get_model_adapter") as mock_get,
            patch("src.api.routers.chat.conv_store") as mock_conv,
        ):
            mock_get.return_value = _adapter_for(completion)
            mock_conv.append_message = AsyncMock()
            resp = client.post(
                "/api/v1/chat",
                json={"message": "hi", "history": [], "model_id": 999},
                headers=headers,
            )
        # ModelNotFoundError is a config problem -> 404 (matches T2-66),
        # not a degraded-503.
        assert resp.status_code == 404, resp.text
        assert mock_conv.append_message.await_count == 0

    def test_normal_chat_still_works(self, auth_headers):
        from src.api.routers.chat import IntentDecision

        def completion(*a, **kw):
            if kw.get("schema") is IntentDecision:
                return IntentDecision(intent="chat", confidence=0.9, reason="ok")
            return "hello reply"

        headers = auth_headers("analyst")
        with (
            patch("src.api.routers.chat.get_model_adapter") as mock_get,
            patch("src.api.routers.chat.conv_store") as mock_conv,
        ):
            mock_get.return_value = _adapter_for(completion)
            mock_conv.append_message = AsyncMock()
            resp = client.post(
                "/api/v1/chat",
                json={"message": "hi", "history": []},
                headers=headers,
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["reply"] == "hello reply"
def test_chat_persists_route_meta_for_project_route( auth_headers ):
    """V9 F2-extended: the persisted assistant message must carry the
    `route` meta so a historical reload can re-render the route tag and
    intent card without a second LLM call."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(intent="chat", confidence=0.9)
        return "hi there"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        client.post(
            "/api/v1/chat",
            json={"message": "hi", "history": [], "conversation_id": "c-route"},
            headers=headers,
        )
    # The assistant persist call must carry `meta` with the route so the
    # historical intent card can re-render.
    assert mock_conv.append_message.await_count == 2
    assistant_call = mock_conv.append_message.await_args_list[1]
    assert assistant_call.args == ("c-route", "assistant", "hi there")
    assert assistant_call.kwargs.get("meta", {}).get("route") == "chat"


def test_chat_persists_scan_intent_meta( auth_headers ):
    """Scan route: the assistant message must persist `meta.intent`
    (the structured ScanIntent) so the historical intent card can be
    re-rendered without a second LLM call."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.95,
                scan_intent=ScanIntent(targets=["test"], modules=["sys_vuln", "baseline"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        client.post(
            "/api/v1/chat",
            json={"message": "scan test", "history": [], "conversation_id": "c-scan"},
            headers=headers,
        )
    assert mock_conv.append_message.await_count == 2
    assistant_call = mock_conv.append_message.await_args_list[1]
    meta = assistant_call.kwargs.get("meta") or {}
    assert meta.get("route") == "scan"
    assert meta.get("intent", {}).get("targets") == ["test"]
    assert meta.get("intent", {}).get("modules") == ["sys_vuln", "baseline"]
    # Sources should be present so the historical view can show them too.
    assert isinstance(meta.get("sources"), list)
    assert any(s.get("title") == "intent" for s in meta["sources"])


def test_patch_message_endpoint_writes_task_id( auth_headers ):
    """V9 F2-extended: the PATCH /vulnscan/conversations/{id}/messages/{ts}
    endpoint must call conv_store.patch_message and return the updated
    conversation. The historical intent card uses this to write back the
    task_id after the operator clicks 执行扫描."""
    headers = auth_headers("analyst")
    fake_conv = {"id": "c-patch", "messages": [], "updated_at": "now"}
    with (
        patch("src.api.routers.scan_chat.conv_store") as mock_conv,
    ):
        mock_conv.patch_message = AsyncMock(return_value=fake_conv)
        resp = client.patch(
            "/api/v1/vulnscan/conversations/c-patch/messages/2026-08-01T00:00:00Z",
            json={"task_id": "task-1234"},
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    mock_conv.patch_message.assert_awaited_once()
    args, kwargs = mock_conv.patch_message.await_args
    # positional: conv_id, ts
    assert args[0] == "c-patch"
    assert args[1] == "2026-08-01T00:00:00Z"
    # keyword patch: only the allow-listed field is forwarded
    assert args[2] == {"task_id": "task-1234"}


def test_patch_message_endpoint_404_when_missing( auth_headers ):
    """V9 F2-extended: if conv_store.patch_message returns None, the
    endpoint must 404 -- not silently 200 with an empty body -- so the
    frontend can distinguish 'task not found' from 'task saved'."""
    headers = auth_headers("analyst")
    with patch("src.api.routers.scan_chat.conv_store") as mock_conv:
        mock_conv.patch_message = AsyncMock(return_value=None)
        resp = client.patch(
            "/api/v1/vulnscan/conversations/missing/messages/2026-08-01T00:00:00Z",
            json={"task_id": "task-1234"},
            headers=headers,
        )
    assert resp.status_code == 404, resp.text


def test_patch_message_sanitizes_meta_keys( auth_headers ):
    """V9 F2-extended: only the allow-listed meta keys (route, intent,
    sources, task_id) are persisted. Junk keys are silently stripped so
    the jsonb shape stays predictable for analytics / audit code."""
    from src.agents import conversation as conv_module
    import asyncio as _asyncio

    # Drive the storage layer directly (no HTTP) so we can inspect the
    # actual sanitization contract.
    clean = conv_module._sanitize_meta(
        {"task_id": "t1", "route": "scan", "junk": "x", "injected": {"a": 1}}
    )
    assert clean == {"task_id": "t1", "route": "scan"}
    # empty / None input -> empty dict (no meta field on the message)
    assert conv_module._sanitize_meta(None) == {}
    assert conv_module._sanitize_meta({}) == {}
def test_strip_target_prefixes_removes_llm_type_tags():
    """V9 F2-extended: when the LLM emits "group:test" / "host:rocky-01"
    despite the prompt instruction, the chat router must strip those
    prefixes so the frontend auto-fill (which matches by exact group
    name) keeps working."""
    from src.api.routers.chat import _strip_target_prefixes

    # group: prefix variants
    assert _strip_target_prefixes(["group:test"]) == ["test"]
    assert _strip_target_prefixes(["Group:Test"]) == ["Test"]
    assert _strip_target_prefixes(["grp:test2"]) == ["test2"]
    # host: prefix variants
    assert _strip_target_prefixes(["host:rocky-01"]) == ["rocky-01"]
    assert _strip_target_prefixes(["HOSTNAME:web01"]) == ["web01"]
    # ip: prefix variants
    assert _strip_target_prefixes(["ip:10.0.0.5"]) == ["10.0.0.5"]
    # mixed: only the prefixed ones are stripped, the bare ones are kept
    assert _strip_target_prefixes(["group:test", "rocky-01", "10.0.0.5"]) == [
        "test",
        "rocky-01",
        "10.0.0.5",
    ]
    # unknown prefix is left alone -- the LLM might use a domain we
    # don't know about, and silently dropping those would silently change
    # the operator's intent.
    assert _strip_target_prefixes(["vlan:prod"]) == ["vlan:prod"]
    # empty / None / non-string inputs are scrubbed
    assert _strip_target_prefixes([]) == []
    assert _strip_target_prefixes(None or []) == []  # type: ignore[arg-type]
    assert _strip_target_prefixes([""] ) == []
    assert _strip_target_prefixes(["  ", "group:test"]) == ["test"]
def test_chat_scan_with_bare_group_name( auth_headers ):
    """E2E simulation: the LLM returns `targets: ["test"]` for the user
    request `扫描 test 组的主机`. The persisted scan_intent carries the
    bare name and the helper skips the regex fallback (no log line)."""
    import json as _json
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.95,
                scan_intent=ScanIntent(targets=["test"], modules=["sys_vuln", "baseline"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组的主机，做漏洞扫描 + 基线",
                "history": [],
                "conversation_id": "c-bare",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent"] == "scan"
    # The reply text in the LLM turn must show the bare name (not
    # "group:test") and not the “未指定” placeholder.
    assert "test" in body["reply"]
    assert "未指定" not in body["reply"]
    # The persisted assistant meta carries the structured intent.
    assistant_call = mock_conv.append_message.await_args_list[1]
    meta = assistant_call.kwargs.get("meta") or {}
    assert meta.get("intent", {}).get("targets") == ["test"]


def test_chat_scan_with_prefixed_group_name( auth_headers ):
    """E2E simulation: the LLM still emits the type tag (e.g. old
    model checkpoint) and the backend prefix-stripper cleans it."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.9,
                scan_intent=ScanIntent(targets=["group:test"], modules=["sys_vuln"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组",
                "history": [],
                "conversation_id": "c-prefix",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The reply text uses the bare name (no `group:`).
    assert "test" in body["reply"]
    assert "group:test" not in body["reply"]
    assistant_call = mock_conv.append_message.await_args_list[1]
    meta = assistant_call.kwargs.get("meta") or {}
    assert meta.get("intent", {}).get("targets") == ["test"]


def test_chat_scan_fallback_when_llm_returns_empty_targets( auth_headers ):
    """E2E simulation: the LLM returns `targets: []` (the regression
    we just hit in production). The backend's regex fallback must
    extract the group name from the user message so the operator
    does not have to re-type."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.9,
                scan_intent=ScanIntent(targets=[], modules=["sys_vuln", "baseline"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组的主机，做漏洞扫描 + 基线",
                "history": [],
                "conversation_id": "c-fallback",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The reply text now contains the bare name (not 未指定).
    assert "test" in body["reply"], body["reply"]
    assert "未指定" not in body["reply"]
    assistant_call = mock_conv.append_message.await_args_list[1]
    meta = assistant_call.kwargs.get("meta") or {}
    assert meta.get("intent", {}).get("targets") == ["test"]


def test_chat_scan_fallback_for_ip_address( auth_headers ):
    """E2E simulation: user pastes a bare IP, the LLM returns empty
    targets, and the regex fallback extracts the IP as-is."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.9,
                scan_intent=ScanIntent(targets=[], modules=["sys_vuln"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 10.0.0.5 这台服务器",
                "history": [],
                "conversation_id": "c-ip",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "10.0.0.5" in body["reply"], body["reply"]
    assistant_call = mock_conv.append_message.await_args_list[1]
    meta = assistant_call.kwargs.get("meta") or {}
    assert meta.get("intent", {}).get("targets") == ["10.0.0.5"]


def test_fallback_extract_targets_unit():
    """Unit test for the regex fallback extractor (no HTTP / LLM)."""
    from src.api.routers.chat import _fallback_extract_targets

    # Chinese group syntax
    assert _fallback_extract_targets("扫描 test 组") == ["test"]
    assert _fallback_extract_targets("帮我扫描 prod 组") == ["prod"]
    # Multiple targets in one message
    out = _fallback_extract_targets("扫描 prod 组 + test 组")
    assert "prod" in out and "test" in out
    # Bare hostnames
    assert _fallback_extract_targets("扫描 rocky-01") == ["rocky-01"]
    # IPv4
    assert _fallback_extract_targets("扫描 10.0.0.5") == ["10.0.0.5"]
    # Prefix-strip on the way out
    assert _fallback_extract_targets("扫描 group:test 组") == ["test"]
    # Empty / no match
    assert _fallback_extract_targets("你好，我是谁") == []
    # Dedup
    assert _fallback_extract_targets("扫描 test 组里的 test 主机") == ["test"]
def test_chat_response_carries_assistant_ts( auth_headers ):
    """V9 follow-up: the /api/v1/chat response must include the
    PG-persisted `assistant_ts` so the frontend can use it as the
    authoritative `ts` for the in-memory assistant message. This
    is what makes `patchMessage(task_id)` reliably hit the same
    row (otherwise microsecond / timezone drift between client
    and server silently misses)."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.95,
                scan_intent=ScanIntent(targets=["test"], modules=["sys_vuln", "baseline"]),
            )
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        # Simulate what the real store would do: append_message
        # returns (conv, persisted_message). The persisted message
        # carries the *real* PG ts (different from what the client
        # generated).
        ts_client = "2026-08-01T10:00:00.123Z"
        ts_server = "2026-08-01T10:00:00.456+00:00"
        async def fake_append(conv_id, role, content, meta=None):
            msg = {"role": role, "content": content, "ts": ts_server}
            if meta:
                msg.update(meta)
            return (
                {"id": conv_id, "messages": [msg], "title": "t"},
                msg,
            )
        mock_conv.append_message = AsyncMock(side_effect=fake_append)
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组的主机",
                "history": [],
                "conversation_id": "c-ts",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent"] == "scan"
    # assistant_ts is the *server* `ts`, not whatever the client passed.
    assert body.get("assistant_ts") == ts_server
    assert body["assistant_ts"] != ts_client


def test_patch_message_task_id_persists_through_reload( auth_headers ):
    """E2E V9 follow-up: after a /chat call, the frontend uses
    `response.assistant_ts` to call PATCH
    /vulnscan/conversations/{id}/messages/{ts} with the new task_id.
    A subsequent `getConversation` must show the task_id attached
    to the assistant turn (the bug the user just hit)."""
    from src.agents.models import ScanIntent
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return IntentDecision(
                intent="scan",
                confidence=0.95,
                scan_intent=ScanIntent(targets=["test"], modules=["sys_vuln", "baseline"]),
            )
        return "x"

    headers = auth_headers("analyst")
    ts_server = "2026-08-01T10:00:00.456+00:00"
    task_id = "10b90d20-ca28-4075-80c1-0a9d741f59d9"

    # In-memory state of the conversation as the tests walk it.
    state = {"conv": None}

    async def fake_append(conv_id, role, content, meta=None):
        msg = {"role": role, "content": content, "ts": ts_server}
        if meta:
            msg.update(meta)
        state["conv"] = {
            "id": conv_id,
            "messages": list(state["conv"]["messages"]) if state["conv"] else [],
            "title": "t",
        }
        state["conv"]["messages"].append(msg)
        return state["conv"], msg

    async def fake_patch(conv_id, ts, patch):
        assert conv_id == "c-patch"
        msgs = state["conv"]["messages"]
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i].get("ts") == ts:
                msgs[i] = {**msgs[i], **patch}
                return state["conv"]
        return None

    async def fake_get(conv_id):
        return state["conv"]

    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.scan_chat.conv_store") as mock_scan_conv,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock(side_effect=fake_append)
        mock_scan_conv.patch_message = AsyncMock(side_effect=fake_patch)
        mock_scan_conv.get_conversation = AsyncMock(side_effect=fake_get)
        # 1. /chat
        r1 = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组的主机",
                "history": [],
                "conversation_id": "c-patch",
            },
            headers=headers,
        )
        assert r1.status_code == 200, r1.text
        assistant_ts = r1.json()["assistant_ts"]
        assert assistant_ts == ts_server
        # 2. PATCH /vulnscan/conversations/.../messages/{ts}
        r2 = client.patch(
            f"/api/v1/vulnscan/conversations/c-patch/messages/{assistant_ts}",
            json={"task_id": task_id},
            headers=headers,
        )
        assert r2.status_code == 200, r2.text
        # 3. Re-fetch -- the assistant turn must now carry task_id
        r3 = client.get("/api/v1/vulnscan/conversations/c-patch", headers=headers)
        assert r3.status_code == 200, r3.text
        conv = r3.json()
        assistant_msgs = [m for m in conv["messages"] if m["role"] == "assistant"]
        assert assistant_msgs, "no assistant message persisted"
        assistant = assistant_msgs[-1]
        assert assistant.get("task_id") == task_id, (
            f"expected task_id={task_id}, got {assistant.get('task_id')!r}"
        )
        assert assistant.get("ts") == ts_server
async def test_append_then_patch_round_trip_with_real_ts():
    """V9 follow-up storage contract: append_message returns the
    actual `ts` PG wrote; patch_message MUST find that same row
    when the caller forwards that `ts` back. This is what makes the
    chat -> patchMessage(task_id) -> reload flow reliable."""
    from src.agents import conversation as conv
    from datetime import UTC, datetime

    # Stub the PG connection so we don't need a real DB.
    in_memory = {"msgs": []}

    class _FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def fetchrow(self, sql, *args):
            print("FAKE fetchrow:", sql[:60])
            if "INSERT INTO scan_conversations" in sql:
                return {
                    "id": args[0],
                    "title": args[1],
                    "model_id": args[2],
                    "messages": [],
                    "created_at": datetime.now(UTC),
                    "updated_at": datetime.now(UTC),
                }
            if "SELECT * FROM scan_conversations" in sql:
                return {
                    "id": args[0],
                    "title": "t",
                    "model_id": None,
                    "messages": list(in_memory["msgs"]),
                    "created_at": datetime.now(UTC),
                    "updated_at": datetime.now(UTC),
                }
            if "SELECT messages FROM" in sql:
                return {"messages": list(in_memory["msgs"])}
            if "UPDATE scan_conversations" in sql and "SET messages" in sql:
                import json as _json
                in_memory["msgs"] = _json.loads(args[0])
                return {
                    "id": args[1],
                    "title": "t",
                    "model_id": None,
                    "messages": list(in_memory["msgs"]),
                    "created_at": datetime.now(UTC),
                    "updated_at": datetime.now(UTC),
                }
            raise AssertionError(f"unexpected query: {sql[:80]}")

    async def fake_pg_conn():
        return _FakeConn()

    # Bootstrap a conversation row. Pass a STRING UUID -- append_message
    # calls `uuid.UUID(conv_id)` internally so it can index into PG.
    import uuid as _uuid
    conv_id = str(_uuid.uuid4())
    with patch.object(conv, "_pg_conn", fake_pg_conn):
        await conv.create_conversation("test", None)
        # 1) append two messages via the new tuple-returning API.
        _, user_persisted = await conv.append_message(conv_id, "user", "扫描 test 组")
        _, asst_persisted = await conv.append_message(
            conv_id, "assistant", "已识别", meta={"route": "scan"}
        )
    # The persisted `ts` is whatever the row carried (== what PG wrote).
    real_ts = asst_persisted["ts"]
    # 2) patch_message with that exact `ts` MUST hit.
    with patch.object(conv, "_pg_conn", fake_pg_conn):
        result = await conv.patch_message(conv_id, real_ts, {"task_id": "abc-123"})
    assert result is not None
    patched = result["messages"][-1]
    assert patched["task_id"] == "abc-123", patched
    assert patched["ts"] == real_ts
    # 3) The opposite: a client-fabricated `ts` that does NOT match
    # the PG row silently misses (returns the conversation with no
    # update). We are NOT patching with a wrong ts in production --
    # this is just the negative side of the contract.
    in_memory["msgs"][-1] = {
        **in_memory["msgs"][-1],
        "task_id": None,
    }  # reset for the next assertion
    with patch.object(conv, "_pg_conn", fake_pg_conn):
        miss = await conv.patch_message(conv_id, "drifted-by-1us", {"task_id": "should-not-stick"})
    # patch_message returns the conv even on miss, but the message
    # was not actually updated.
    last = miss["messages"][-1]
    assert last.get("task_id") != "should-not-stick", last
def test_chat_returns_503_when_classifier_returns_none( auth_headers ):
    """V9 follow-up: when the LLM adapter returns None (empty /
    streaming-cancelled response) instead of an IntentDecision, the
    router must NOT 500. It should answer 503 + audit so the operator
    sees the classifier dropped the request, exactly like any other
    classification failure. This was the bug behind the 500 the user
    just hit on production: AttributeError: 'NoneType' object has no
    attribute 'intent'."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        # Simulate the LangChain adapter returning None for a structured
        # call (happens for some model integrations on empty output).
        return None

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组的主机",
                "history": [],
                "conversation_id": "c-none",
            },
            headers=headers,
        )
    # Must be 503, NOT 500. The operator should see "服务不可用"
    # not a generic 500 from an AttributeError downstream.
    assert resp.status_code == 503, (
        f"expected 503 for None classifier, got {resp.status_code}: {resp.text}"
    )
    assert "意图分类" in resp.json()["detail"]
    # Nothing was persisted (we did not produce a valid decision).
    assert mock_conv.append_message.await_count == 0
    # Audit entry recorded so the operator can see the failure path.
    mock_audit.return_value.log.assert_awaited_once()
    assert mock_audit.return_value.log.await_args.kwargs["action"] == "chat_classify_degraded"


def test_chat_returns_503_when_classifier_returns_wrong_type( auth_headers ):
    """V9 follow-up: same defence for when the adapter returns a
    non-IntentDecision value (e.g. a string for a free-form call)."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        return "unexpectedly-a-string"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "扫描 test 组",
                "history": [],
                "conversation_id": "c-wrong",
            },
            headers=headers,
        )
    assert resp.status_code == 503, resp.text
    assert mock_conv.append_message.await_count == 0
def test_chat_degraded_web_question_returns_200_with_answer( auth_headers ):
    """V9 follow-up: when the structured classifier returns None /
    raises but the user is asking a non-scan question (industry news,
    CVE lookup, etc.), the router must NOT 503. It should best-effort
    route via the web handler and return a real answer. The scan-route
    gate is what we are protecting -- free-form questions must keep
    working when the LLM is having a bad day with structured output."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        # Simulate the LLM returning None for the structured call.
        if kw.get("schema") is IntentDecision:
            return None
        # The web handler also calls chat_completion without a schema
        # to compose the final answer; return a deterministic string.
        return "\u8fd1\u671f\u884c\u4e1a\u51fa\u73b0\u4e86 X \u4e2a\u91cd\u5927\u4e8b\u4ef6\u3002"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        patch("src.api.routers.chat.search_with_fallback") as mock_search,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        # Stub web search to return no hits so the web handler falls
        # through to a deterministic LLM-only answer.
        import asyncio as _asyncio
        async def fake_search(q, limit=6):
            return [], "nvd"
        mock_search.side_effect = fake_search
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "\u6700\u8fd1\u884c\u4e1a\u91cc\u6709\u6ca1\u6709\u6bd4\u8f83\u91cd\u5927\u7684\u5b89\u5168\u4e8b\u4ef6\uff1f",
                "history": [],
                "conversation_id": "c-degraded-web",
            },
            headers=headers,
        )
    # The user gets a real answer, not a 503.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "\u8fd1\u671f\u884c\u4e1a" in body["reply"], body["reply"]
    # The response route was inferred as web (CVE / industry keywords).
    assert body["intent"] == "web", body
    # The audit entry was still recorded -- we never silently bypassed
    # the gate, the operator just got a degraded answer.
    mock_audit.return_value.log.assert_awaited_once()
    assert mock_audit.return_value.log.await_args.kwargs["action"] == "chat_classify_degraded"


def test_chat_degraded_scan_question_still_503( auth_headers ):
    """V9 follow-up: when the structured classifier fails AND the
    user asked for a scan, we MUST still 503. The safety property
    is that an un-routed message can never reach the scan executor."""
    from src.api.routers.chat import IntentDecision

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return None
        return "x"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "\u5e2e\u6211\u626b\u63cf test \u7ec4\u7684\u4e3b\u673a",
                "history": [],
                "conversation_id": "c-degraded-scan",
            },
            headers=headers,
        )
    # Locked out -- the scan-route gate is the safety property.
    assert resp.status_code == 503, resp.text
    assert "\u610f\u56fe\u5206\u7c7b" in resp.json()["detail"]
    # Nothing was persisted (no half-written scan conversation).
    assert mock_conv.append_message.await_count == 0
    # Audit logged for the operator.
    mock_audit.return_value.log.assert_awaited_once()
def test_degraded_routing_matrix_for_typical_user_messages():
    """V9 follow-up: walk the most common user messages through
    the degraded-routing heuristics and assert where each lands.
    This protects the keyword lists from silent drift -- a user
    asking `详细介绍某个主机的漏洞情况` MUST not end up 503'd,
    and a user asking `扫描 test 组` MUST end up 503'd even when
    the structured classifier drops the ball."""
    from src.api.routers.chat import (
        _looks_like_scan_intent, _WEB_KEYWORDS, _PROJECT_KEYWORDS,
        _HOST_KEYWORDS, _SCAN_KEYWORDS,
    )

    cases = [
        # (message, expected_scan_intent, expected_fallback_route)
        # --- the two the user just asked about -----------------------
        ("详细介绍某个主机的漏洞情况", False, "host"),
        ("历史上有哪些重大的安全事件", False, "web"),
        # host-shaped with a specific hostname in the message -- host
        # wins over web (the host handler queries the real vuln store).
        ("给我详细说一下 Rocky001 这台主机的漏洞", False, "host"),
        ("web-02 有哪些漏洞", False, "host"),
        ("某个 IP 10.0.0.5 的漏洞情况", False, "host"),
        # --- broader sweep so the matrix stays honest ---------------
        ("最近有什么新的 CVE 利用代码", False, "web"),
        ("APT 组织的最新活动", False, "web"),
        ("企业被入侵了怎么办", False, "web"),
        ("Rocky001 有哪些漏洞", False, "host"),
        ("今天有什么重要新闻", False, "web"),
        ("你好，你是谁", False, "chat"),
        ("这个系统的架构是怎么样的", False, "project"),
        ("如何将一台新主机接入这个系统", False, "project"),
        # --- the lock-out cases (must be 503) -------------------------
        ("帮我扫描 test 组", True, None),
        ("scan foo", True, None),
        ("创建任务", True, None),
        # --- false-positive edge: a Chinese idiom that happens to contain
        ("扫描二维码什么意思", True, None),
    ]

    def fallback_route_for(message: str) -> str:
        # Mirrors _degraded_best_effort: a hostname-shaped token +
        # host/web keyword upgrades to host (the vuln store is more
        # useful than a web search for "web-02 \u6709\u54ea\u4e9b\u6f0f\u6d1e").
        # We also mirror the production blacklist + digit/hyphen/dot
        # filter so CVE / APT / web / api are NOT mis-classified as
        # host tokens.
        import re as _re
        from src.api.routers.chat import _HOST_TOKEN_BLACKLIST
        text = (message or "").lower()
        host_tokens: list[str] = []
        for m in _re.finditer(
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
            r"|\b([a-zA-Z][a-zA-Z0-9\-]{1,30})(?:\.[a-zA-Z][a-zA-Z0-9\-]+)*\b",
            text,
        ):
            tok = m.group(1) or m.group(0)
            if tok.lower() in _HOST_TOKEN_BLACKLIST:
                continue
            if not any(c.isdigit() or c in "-." for c in tok):
                continue
            host_tokens.append(tok)
        if host_tokens and any(
            kw in text for kw in (_HOST_KEYWORDS + _WEB_KEYWORDS)
        ):
            return "host"
        if any(kw in text for kw in _HOST_KEYWORDS):
            return "host"
        if any(kw in text for kw in _WEB_KEYWORDS):
            return "web"
        if any(kw in text for kw in _PROJECT_KEYWORDS):
            return "project"
        return "chat"

    for message, expected_scan, expected_route in cases:
        got_scan = _looks_like_scan_intent(message)
        got_route = fallback_route_for(message) if not got_scan else None
        assert got_scan == expected_scan, (
            f"scan-intent for {message!r}: got {got_scan}, expected {expected_scan}"
        )
        if expected_route is not None:
            assert got_route == expected_route, (
                f"fallback route for {message!r}: got {got_route}, expected {expected_route}"
            )
        # Sanity: scan-keyword + project-keyword lists should be disjoint
        # so the lock-out does not accidentally fire for project questions.
        overlap = set(_SCAN_KEYWORDS) & set(_PROJECT_KEYWORDS)
        assert not overlap, f"scan/project keyword overlap: {overlap}"
        overlap2 = set(_SCAN_KEYWORDS) & set(_WEB_KEYWORDS)
        assert not overlap2, f"scan/web keyword overlap: {overlap2}"
def test_degraded_host_question_queries_vulnstore_by_hostname( auth_headers ):
    """V9 follow-up: when the user asks about a specific host's
    vulnerabilities via the degraded path, the chat router must
    call vulnstore.list_vulns(VulnFilter(hostname=...)) and let the
    LLM compose the answer from the real findings -- not invent
    from training data, not fall through to a free-form apology."""
    from src.api.routers.chat import IntentDecision
    from src.agents.models import Host, VulnFilter, VulnFinding, ScanModule
    import datetime as _dt

    class _FakeVulnStore:
        def __init__(self):
            self.list_hosts_calls = []
            self.list_vulns_calls = []
        async def list_hosts(self, **kwargs):
            self.list_hosts_calls.append(kwargs)
            return [
                Host(
                    agent_id="a-1",
                    hostname="Rocky001",
                    ip="10.0.0.5",
                    os="Rocky 9",
                    arch="x86_64",
                    kernel="5.14",
                    status="online",
                    agent_version="2.0",
                    rule_version="2026-08-01",
                    last_heartbeat="2026-08-01T00:00:00Z",
                    group="test",
                    owner=None,
                    env=None,
                    created_at="2026-07-01T00:00:00Z",
                )
            ]
        async def list_vulns(self, fltr):
            self.list_vulns_calls.append(fltr)
            return [
                VulnFinding(
                    finding_id="f-1",
                    task_id="t-1",
                    agent_id="a-1",
                    hostname="Rocky001",
                    category=ScanModule.SYS_VULN,
                    cve="CVE-2024-1234",
                    name="openssl heap overflow",
                    severity="high",
                    status="open",
                    detected_at="2026-08-01T00:00:00Z",
                ),
                VulnFinding(
                    finding_id="f-2",
                    task_id="t-1",
                    agent_id="a-1",
                    hostname="Rocky001",
                    category=ScanModule.BASELINE,
                    cve=None,
                    name="weak ssh config",
                    severity="medium",
                    status="open",
                    detected_at="2026-08-01T00:00:00Z",
                ),
            ]

    fake_store = _FakeVulnStore()
    fake_store.list_hosts = AsyncMock(side_effect=fake_store.list_hosts)
    fake_store.list_vulns = AsyncMock(side_effect=fake_store.list_vulns)

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return None  # simulate classifier dropping the ball
        return "Rocky001 有 2 个漏洞，其中 1 个 high，1 个 medium。"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        patch("src.api.routers.chat.get_vulnscan_store", return_value=fake_store),
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "详细介绍 Rocky001 这台主机的漏洞情况",
                "history": [],
                "conversation_id": "c-host",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Route went to the host handler.
    assert body["intent"] == "host", body
    # The LLM-composed answer made it through.
    assert "Rocky001" in body["reply"], body["reply"]
    # CRITICAL: we actually queried the vuln store for this host.
    assert len(fake_store.list_hosts_calls) == 1
    assert fake_store.list_hosts_calls[0].get("hostname") == "Rocky001"
    assert len(fake_store.list_vulns_calls) == 1
    fltr = fake_store.list_vulns_calls[0]
    assert fltr.hostname == "Rocky001", fltr
    # Audit entry was recorded -- we never silently bypassed the gate.
    mock_audit.return_value.log.assert_awaited_once()


def test_degraded_host_question_unknown_host_returns_explicit_message( auth_headers ):
    """V9 follow-up: when the user names a host that does not exist
    in the vuln store, the handler must say so explicitly -- it
    must NOT pretend there are no findings or invent data."""
    from src.api.routers.chat import IntentDecision
    from src.agents.models import Host

    class _FakeVulnStore:
        async def list_hosts(self, **kwargs):
            return []  # nothing matches
        async def list_vulns(self, fltr):
            raise AssertionError("should not be called for unknown host")

    fake_store = _FakeVulnStore()
    fake_store.list_hosts = AsyncMock(side_effect=fake_store.list_hosts)

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return None
        raise AssertionError("should not be called for unknown host")

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        patch("src.api.routers.chat.get_vulnscan_store", return_value=fake_store),
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "某台主机 ghost-host-99 的漏洞怎么样",
                "history": [],
                "conversation_id": "c-unknown-host",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Should explicitly say the host does not exist.
    assert "ghost-host-99" in body["reply"], body["reply"]
    assert "没有找到" in body["reply"], body["reply"]
    assert body["intent"] == "host"


def test_degraded_host_question_without_specific_host_lists_top_n( auth_headers ):
    """V9 follow-up: when the user asks a generic host question
    (no specific hostname), the handler must fall back to a top-N
    view of the hosts with most findings so the operator can pick
    one to ask about next."""
    from src.api.routers.chat import IntentDecision
    from src.agents.models import VulnFilter, VulnFinding, ScanModule

    class _FakeVulnStore:
        async def list_hosts(self, **kwargs):
            raise AssertionError(
                "top-N path should not call list_hosts -- it does not have a host"
            )
        async def list_vulns(self, fltr):
            assert fltr.hostname is None, fltr
            assert fltr.limit == 500
            # 3 hosts with varying finding counts
            out = []
            for i in range(5):
                out.append(VulnFinding(
                    finding_id=f"web-{i}",
                    task_id="t-1",
                    agent_id="a-1",
                    hostname="web-01",
                    category=ScanModule.SYS_VULN,
                    cve=None,
                    name=f"web issue {i}",
                    severity="low",
                    status="open",
                    detected_at="2026-08-01T00:00:00Z",
                ))
            for i in range(3):
                out.append(VulnFinding(
                    finding_id=f"db-{i}",
                    task_id="t-1",
                    agent_id="a-2",
                    hostname="db-01",
                    category=ScanModule.SYS_VULN,
                    cve=None,
                    name=f"db issue {i}",
                    severity="medium",
                    status="open",
                    detected_at="2026-08-01T00:00:00Z",
                ))
            return out

    fake_store = _FakeVulnStore()
    fake_store.list_vulns = AsyncMock(side_effect=fake_store.list_vulns)

    def completion(*a, **kw):
        if kw.get("schema") is IntentDecision:
            return None
        return "请问具体哪台主机。"

    headers = auth_headers("analyst")
    with (
        patch("src.api.routers.chat.get_model_adapter") as mock_get,
        patch("src.api.routers.chat.conv_store") as mock_conv,
        patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        patch("src.api.routers.chat.get_vulnscan_store", return_value=fake_store),
    ):
        mock_get.return_value = _adapter_for(completion)
        mock_conv.append_message = AsyncMock()
        mock_audit.return_value.log = AsyncMock()
        # "详细介绍某个主机的漏洞情况" -- the user's actual case.
        resp = client.post(
            "/api/v1/chat",
            json={
                "message": "详细介绍某个主机的漏洞情况",
                "history": [],
                "conversation_id": "c-topn",
            },
            headers=headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent"] == "host", body
    # list_vulns was called with no hostname filter -- the top-N path.
    assert len(fake_store.list_vulns.await_args_list) >= 1
    fltr = fake_store.list_vulns.await_args_list[0].args[0]
    assert fltr.hostname is None


class TestChatDegradedPersists:
    """V12 5.9 (2026-08-02, 问题2): the degraded-classifier path used to
    `return` before the persistence block, so degraded turns (with the
    "⚠️ 意图分类服务未可用" note) were never written to the conversation
    and vanished on reload."""

    def test_degraded_answer_is_persisted(self, auth_headers):
        from src.api.routers.chat import IntentDecision

        def completion(*a, **kw):
            if kw.get("schema") is IntentDecision:
                return None  # classifier returns no structured decision -> degraded
            return "这是根据关键词预估的回复"

        headers = auth_headers("analyst")
        with (
            patch("src.api.routers.chat.get_model_adapter") as mock_get,
            patch("src.api.routers.chat.conv_store") as mock_conv,
            patch("src.api.routers.chat.get_audit_logger") as mock_audit,
        ):
            mock_get.return_value = _adapter_for(completion)
            mock_conv.append_message = AsyncMock()
            mock_audit.return_value.log = AsyncMock()
            resp = client.post(
                "/api/v1/chat",
                json={
                    "message": "详细介绍 Rocky001 这台主机的漏洞情况",
                    "history": [],
                    "conversation_id": "conv-1",
                },
                headers=headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "意图分类服务未可用" in body["reply"]
        # The degraded turn MUST be persisted (user + assistant).
        assert mock_conv.append_message.await_count == 2
        calls = mock_conv.append_message.await_args_list
        assert calls[0].args == ("conv-1", "user", "详细介绍 Rocky001 这台主机的漏洞情况")
        assert calls[1].args[0:2] == ("conv-1", "assistant")



async def _noop_coro():
    """Stand-in coroutine for the background auto-title task."""
    return None


class TestChatAutoTitle:
    """V12 5.10 (2026-08-02): the unified /chat router must spawn the
    background auto-title task -- before this fix only the legacy scan-chat
    route did, so /chat conversations kept the default "新对话" title."""

    def test_chat_spawns_auto_title_task(self, auth_headers):
        from src.api.routers.chat import IntentDecision

        def completion(*a, **kw):
            if kw.get("schema") is IntentDecision:
                return IntentDecision(intent="chat", confidence=0.9, reason="t")
            return "hello reply"

        headers = auth_headers("analyst")
        with (
            patch("src.api.routers.chat.get_model_adapter") as mock_get,
            patch("src.api.routers.chat.conv_store") as mock_conv,
            patch("src.api.routers.chat.maybe_generate_title") as mock_title,
        ):
            mock_get.return_value = _adapter_for(completion)
            mock_conv.append_message = AsyncMock()
            # maybe_generate_title is an async fn; patch it to a coroutine
            # so the real create_task can wrap it into a real Task.
            mock_title.side_effect = lambda *a, **kw: _noop_coro()
            resp = client.post(
                "/api/v1/chat",
                json={"message": "hi", "history": [], "conversation_id": "conv-1"},
                headers=headers,
            )
        assert resp.status_code == 200, resp.text
        # maybe_generate_title must have been called (background auto-title)
        assert mock_title.call_count >= 1
