"""Unit tests for nuclei_templates (ES-only storage): zip parsing + manifest + ingest.

Covers pure-Python parsing + ES manifest IO via mocks. No live Nacos/ES needed.
"""

import io
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.nuclei_templates import (
    TemplateMeta,
    _acquire_sync_lock,
    _category_of,
    _ingest,
    _parse_yaml_meta,
    _release_sync_lock,
    parse_templates_zip,
    search_manifest,
)

_SAMPLE_YAML = """\
id: CVE-2024-1234
info:
  name: Example RCE
  author: tester
  severity: high
  tags: cve,cve2024,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}"
"""


def _make_zip(wrapper: str, files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"{wrapper}/{name}", data)
    return buf.getvalue()


# -- yaml meta --


def test_parse_yaml_meta_extracts_header():
    meta = _parse_yaml_meta(_SAMPLE_YAML)
    assert meta["template_id"] == "CVE-2024-1234"
    assert meta["name"] == "Example RCE"
    assert meta["severity"] == "high"
    assert meta["tags"] == ["cve", "cve2024", "rce"]
    assert meta["author"] == "tester"


def test_parse_yaml_meta_handles_list_tags():
    meta = _parse_yaml_meta("id: x\ninfo:\n  name: n\n  severity: low\n  tags: [a, b]\n")
    assert meta["tags"] == ["a", "b"]


def test_parse_yaml_meta_invalid_returns_empty():
    # 非 dict（如列表）/ 解析失败 -> 空 dict，不抛异常
    assert _parse_yaml_meta("[1, 2, 3]") == {}
    assert _parse_yaml_meta("not: valid: yaml: :\n  - broken") == {}


# -- category / zip --


def test_category_of():
    assert _category_of("cves/2024/x.yaml") == "cves"
    assert _category_of("workflows/wf.yaml") == "workflows"
    assert _category_of("root.yaml") == "misc"


def test_parse_templates_zip_strips_wrapper_and_detects_version():
    zip_bytes = _make_zip(
        "nuclei-templates-10.4.6",
        {
            "cves/2024/CVE-2024-1234.yaml": _SAMPLE_YAML,
            "README.md": "ignore me",
            "workflows/wf.yaml": "id: wf-1\ninfo:\n  name: wf\n  severity: info\n",
        },
    )
    items, ver = parse_templates_zip(zip_bytes)
    assert ver == "10.4.6"
    paths = sorted(it.path for it in items)
    assert paths == ["cves/2024/CVE-2024-1234.yaml", "workflows/wf.yaml"]
    cve = next(it for it in items if it.path.startswith("cves"))
    assert cve.category == "cves"
    assert cve.template_id == "CVE-2024-1234"
    assert cve.severity == "high"
    assert cve.content == _SAMPLE_YAML
    assert cve.version == "10.4.6"


def test_parse_templates_zip_bad_zip_raises():
    with pytest.raises(ValueError):
        parse_templates_zip(b"not a zip")


def test_parse_templates_zip_skips_non_template_yaml():
    """没有 id 字段的非模板 yaml（.pre-commit-config.yml 等）不入库。"""
    zip_bytes = _make_zip(
        "nuclei-templates-10.4.6",
        {
            "cves/2024/CVE-2024-1.yaml": _SAMPLE_YAML,
            ".pre-commit-config.yml": "repos:\n  - repo: x\n",
            "LICENSE.yaml": "some: text\n",
        },
    )
    items, _ = parse_templates_zip(zip_bytes)
    assert [it.path for it in items] == ["cves/2024/CVE-2024-1.yaml"]


def test_doc_includes_content():
    """ES 是模板库的唯一存储，doc 必须含 content（列表查询时用 _source 排除提速）。"""
    item = TemplateMeta(path="cves/x.yaml", category="cves", template_id="x", content="big yaml body")
    doc = item.doc()
    assert doc["content"] == "big yaml body"
    assert doc["path"] == "cves/x.yaml"


# -- ES manifest search --


@pytest.mark.asyncio
async def test_search_manifest_returns_empty_when_index_missing():
    """索引不存在（未导入过）时返回空，不抛 404 -> 列表页显示空态而非 500。"""
    es = MagicMock()
    es.search = AsyncMock(side_effect=Exception("404 index_not_found"))
    es.close = AsyncMock()
    with patch("src.agents.nuclei_templates._es", return_value=es):
        res = await search_manifest(page=1, size=20)
    assert res["items"] == []
    assert res["total"] == 0


@pytest.mark.asyncio
async def test_search_manifest_returns_hits_and_excludes_content():
    es = MagicMock()
    es.search = AsyncMock(
        return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [{"_source": {"path": "cves/x.yaml", "category": "cves", "template_id": "x"}}],
            }
        }
    )
    es.close = AsyncMock()
    with patch("src.agents.nuclei_templates._es", return_value=es):
        res = await search_manifest(category="cves", q="x", page=1, size=20)
    assert res["total"] == 1
    assert res["items"][0]["path"] == "cves/x.yaml"
    kw = es.search.await_args.kwargs
    assert kw.get("ignore_unavailable") is True
    # sort 必须用 .keyword（text 字段不能排序）；列表排除 content 提速。
    assert kw["sort"] and "category.keyword" in kw["sort"][0]
    assert kw.get("source") == {"excludes": ["content"]}


# -- ingest --


@pytest.mark.asyncio
async def test_ingest_rebuilds_es_and_verifies():
    """_ingest 重建 ES 索引 + 记版本 + 校对实际条数。"""
    items = [
        TemplateMeta(path="cves/a.yaml", category="cves", template_id="a", content="id: a"),
        TemplateMeta(path="cves/b.yaml", category="cves", template_id="b", content="id: b"),
    ]
    with (
        patch("src.agents.nuclei_templates.rebuild_manifest", new=AsyncMock(return_value=2)),
        patch("src.agents.nuclei_templates._count_manifest", new=AsyncMock(return_value=2)),
        patch("src.agents.nuclei_templates._set_version", new=AsyncMock()),
    ):
        result = await _ingest(items, "10.4.6")
    assert result["count"] == 2
    assert result["indexed"] == 2
    assert result["es_actual"] == 2
    assert result["matched"] is True


@pytest.mark.asyncio
async def test_ingest_reports_mismatch_when_count_differs():
    items = [TemplateMeta(path="cves/a.yaml", category="cves", template_id="a", content="id: a")]
    with (
        patch("src.agents.nuclei_templates.rebuild_manifest", new=AsyncMock(return_value=1)),
        patch("src.agents.nuclei_templates._count_manifest", new=AsyncMock(return_value=0)),
        patch("src.agents.nuclei_templates._set_version", new=AsyncMock()),
        patch("src.agents.nuclei_templates.asyncio.sleep", new=AsyncMock()),
        patch("src.agents.nuclei_templates.get_audit_logger") as mock_audit,
        patch("src.agents.nuclei_templates._redis") as mock_redis,
    ):
        mock_audit.return_value.log = AsyncMock()
        mock_redis.return_value.publish = AsyncMock()
        result = await _ingest(items, "10.4.6")
    assert result["es_actual"] == 0
    assert result["matched"] is False  # 校对发现丢条
    # Spec-P1-NUKE (V12): partial sync must be surfaced, not silently logged.
    mock_audit.return_value.log.assert_awaited_once()
    assert (
        mock_audit.return_value.log.await_args.kwargs["action"]
        == "nuclei_templates_partial_sync"
    )
    mock_redis.return_value.publish.assert_awaited_once()
    drift_msg = mock_redis.return_value.publish.await_args.args[1]
    assert "nuclei_templates_sync_drift" in drift_msg


async def test_ingest_matched_when_count_equal_or_greater():
    """Spec-P1-NUKE: >= tolerance (ES count may briefly exceed after refresh)
    must NOT trigger a false drift alarm."""
    items = [TemplateMeta(path="cves/a.yaml", category="cves", template_id="a", content="id: a")]
    with (
        patch("src.agents.nuclei_templates.rebuild_manifest", new=AsyncMock(return_value=1)),
        patch("src.agents.nuclei_templates._count_manifest", new=AsyncMock(return_value=1)),
        patch("src.agents.nuclei_templates._set_version", new=AsyncMock()),
        patch("src.agents.nuclei_templates.get_audit_logger") as mock_audit,
        patch("src.agents.nuclei_templates._redis") as mock_redis,
    ):
        mock_audit.return_value.log = AsyncMock()
        mock_redis.return_value.publish = AsyncMock()
        result = await _ingest(items, "10.4.6")
    assert result["matched"] is True
    mock_audit.return_value.log.assert_not_awaited()
    mock_redis.return_value.publish.assert_not_awaited()


# -- sync lock --


@pytest.mark.asyncio
async def test_sync_lock_prevents_concurrent():
    """同步锁：首次获取成功，未释放前第二次失败，释放后可再获取。防止重复点击叠加。"""
    held = {"v": False}

    class _FakeRedis:
        async def set(self, key, val, ex=None, nx=False):  # noqa: ARG002
            if nx and not held["v"]:
                held["v"] = True
                return True
            return False

        async def delete(self, key):  # noqa: ARG002
            held["v"] = False
            return 1

        async def aclose(self):
            return None

    with patch("src.agents.nuclei_templates._redis", return_value=_FakeRedis()):
        assert await _acquire_sync_lock() is True
        assert await _acquire_sync_lock() is False
        await _release_sync_lock()
        assert await _acquire_sync_lock() is True


# -- S-P1-6 / S-P1-EDIT (V12): zip-bomb guards + save_template YAML validation --


def test_parse_templates_zip_rejects_too_many_entries():
    """超过 50k 条目的 zip 直接拒绝（zip 炸弹防护），不逐条 inflate。"""
    from src.agents.nuclei_templates import MAX_ZIP_ITEMS

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(MAX_ZIP_ITEMS + 1):
            zf.writestr(f"cves/{i}.yaml", _SAMPLE_YAML)
    with pytest.raises(ValueError, match="exceeds"):
        parse_templates_zip(buf.getvalue())


def test_parse_templates_zip_rejects_huge_uncompressed_size():
    """500MB 解压上限：file_size 虚高的条目拒绝（不真实解压）。"""
    from src.agents.nuclei_templates import MAX_ZIP_UNCOMPRESSED_BYTES

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # 单个条目声称 600MB（zip bomb 的典型形态：小压缩比，大 file_size）
        zf.writestr("cves/bomb.yaml", _SAMPLE_YAML)
        zf.infolist()[-1].file_size = MAX_ZIP_UNCOMPRESSED_BYTES + 1
    with pytest.raises(ValueError, match="exceeds"):
        parse_templates_zip(buf.getvalue())


async def test_save_template_rejects_invalid_yaml():
    from src.agents.nuclei_templates import save_template

    with (
        patch("src.agents.nuclei_templates.get_template_doc", AsyncMock(return_value=None)),
        pytest.raises(ValueError, match="invalid YAML"),
    ):
        await save_template("cves/x.yaml", "this is : not: [valid: yaml")


async def test_save_template_rejects_missing_id():
    from src.agents.nuclei_templates import save_template

    with (
        patch("src.agents.nuclei_templates.get_template_doc", AsyncMock(return_value=None)),
        pytest.raises(ValueError, match="id"),
    ):
        await save_template("cves/x.yaml", "info:\n  name: no id here\n")


async def test_save_template_accepts_valid_yaml():
    from src.agents.nuclei_templates import save_template

    with (
        patch("src.agents.nuclei_templates.get_template_doc", AsyncMock(return_value=None)),
        patch("src.agents.nuclei_templates.upsert_template", AsyncMock()) as mock_upsert,
    ):
        result = await save_template("cves/CVE-2024-1.yaml", _SAMPLE_YAML)
    assert result["ok"] is True
    assert result["template_id"] == "CVE-2024-1234"
    mock_upsert.assert_awaited_once()


async def test_sync_from_mirror_rejects_oversized_zip():
    from src.agents.nuclei_templates import MAX_ZIP_UNCOMPRESSED_BYTES, sync_from_mirror

    settings = MagicMock()
    settings.nuclei_download_base_url = "http://mirror:8081"
    settings.nuclei_templates_version = "10.4.6"

    class FakeResp:
        status_code = 200
        content = b"x" * (MAX_ZIP_UNCOMPRESSED_BYTES + 1)

    with (
        patch("src.agents.nuclei_templates.get_settings", return_value=settings),
        patch("src.agents.nuclei_templates._acquire_sync_lock", AsyncMock(return_value=True)),
        patch("src.agents.nuclei_templates._release_sync_lock", AsyncMock()),
        patch(
            "httpx.AsyncClient",
            MagicMock(
                return_value=MagicMock(
                    __aenter__=AsyncMock(return_value=MagicMock(get=AsyncMock(return_value=FakeResp())))
                )
            ),
        ),
        pytest.raises(RuntimeError, match="上限"),
    ):
        await sync_from_mirror()
