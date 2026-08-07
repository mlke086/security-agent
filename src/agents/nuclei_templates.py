"""Nuclei 模板库管理（ES 单一存储）。

模板的元数据 + 原文 content 全部存 ES ``nuclei-templates`` 索引（每条一个文档，
``_id``=模板路径）。列表/搜索走 ES（按 CVE/名称/路径全文搜），详情/编辑走 ES。
13k+ 模板对 ES 毫无压力，避免了 Nacos 方案的 dataId 限制 / 控制台淹没 / 无全文搜索问题。

数据来源：
  - 联网更新：从内网下载站拉 nuclei-templates-{version}.zip
  - 手动导入：上传 zip
两者都：解析 zip -> 批量索引到 ES（重建索引，天然清理旧条目）-> 记版本到 Redis。
编辑只改 ES（本地），不下发到 agent（agent 仍走整包 nuclei_templates_update）。
"""

from __future__ import annotations

import asyncio
import io
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

INDEX_NUCLEI_TEMPLATES = "nuclei-templates"
_VERSION_KEY = "nuclei_templates:library_version"
_SYNC_LOCK_KEY = "nuclei_templates:sync_lock"
_SYNC_LOCK_TTL = 600  # 10min 安全兜底，防异常未释放

# S-P1-6 (V12): zip-bomb guards. A real 13k-template bundle is ~200MB /
# 13k files; these caps reject maliciously inflated archives at parse time
# (the router also rejects by Content-Length before buffering).
MAX_ZIP_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_ZIP_ITEMS = 50_000


# --------------------------------------------------------------------- models


@dataclass
class TemplateMeta:
    """一条 nuclei 模板：元数据 + 原文。content 一并存 ES（本地存储）。"""

    path: str  # 去掉顶层目录后的相对路径，如 cves/2024/CVE-2024-1234.yaml
    category: str  # 顶层分类，如 cves / exposures / workflows
    template_id: str = ""
    name: str = ""
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = ""
    version: str = ""
    content: str = ""  # YAML 原文

    def doc(self) -> dict[str, Any]:
        """ES 文档（含 content）。列表查询时用 _source 排除 content 提速。"""
        return {
            "path": self.path,
            "category": self.category,
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "tags": self.tags,
            "author": self.author,
            "version": self.version,
            "content": self.content,
            "updated_at": datetime.now(UTC).isoformat(),
        }


# --------------------------------------------------------------------- clients


# S-P1-8 / S-P1-1 (V12): shared lazy clients. Every API call used to build
# and close its own ES + redis connection (~8 connects per sync); one reused
# client per backend is the VulnscanStore pattern and is safe for these
# non-subscription operations.
_es_client = None
_redis_client = None


def _es() -> AsyncElasticsearch:
    global _es_client
    if _es_client is None:
        _es_client = AsyncElasticsearch(hosts=[get_settings().es_hosts])
    return _es_client


def _redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


async def _set_version(version: str) -> None:
    await _redis().set(_VERSION_KEY, version)


async def current_version() -> str:
    value = await _redis().get(_VERSION_KEY)
    # decode_responses=True returns str|None; stay safe if bytes.
    return value.decode() if isinstance(value, bytes) else (value or "")


async def _acquire_sync_lock() -> bool:
    return bool(await _redis().set(_SYNC_LOCK_KEY, "1", ex=_SYNC_LOCK_TTL, nx=True))


async def _release_sync_lock() -> None:
    await _redis().delete(_SYNC_LOCK_KEY)


# --------------------------------------------------------------------- ES manifest


_INDEX_PREFIX = "nuclei-templates-v"


async def _alias_backing(es) -> str | None:
    """The backing index the ``nuclei-templates`` alias currently points
    at, or None when the alias does not exist yet (first sync)."""
    try:
        resp = await es.indices.get_alias(name=INDEX_NUCLEI_TEMPLATES)
        for name in resp:
            return name
    except Exception:
        return None
    return None


async def rebuild_manifest(items: list[TemplateMeta]) -> int:
    """原子重建 ES 索引（V13 P1-9）——alias-swap 双索引切换。

    流程：写新 backing 索引 -> 原子 update_aliases 切换 -> 删旧索引。
    相比旧的「删索引 -> bulk」：任何时刻 alias 都指向一个完整可搜索
    的索引，中途失败/崩溃不会留下空索引（同步期间并发搜索无空窗），
    失败时旧索引继续服务，半成品新索引被清理。
    """
    if not items:
        return 0
    es = _es()
    new_name = f"{_INDEX_PREFIX}{int(time.time())}"
    try:
        await es.indices.create(index=new_name)
    except Exception as exc:
        raise RuntimeError(f"create backing index {new_name}: {exc}") from exc
    actions = [
        {"_index": new_name, "_id": it.path, "_source": it.doc()} for it in items
    ]
    try:
        await async_bulk(es, actions, refresh="wait_for")
    except Exception:
        # Bulk failed: drop the half-written index, leave the old alias
        # (and its backing index) serving as-is.
        try:
            await es.indices.delete(index=new_name, ignore_unavailable=True)
        except Exception:
            pass
        raise
    old_backing = await _alias_backing(es)
    alias_actions = []
    if old_backing and old_backing != new_name:
        alias_actions.append(
            {"remove": {"index": old_backing, "alias": INDEX_NUCLEI_TEMPLATES}}
        )
    alias_actions.append({"add": {"index": new_name, "alias": INDEX_NUCLEI_TEMPLATES}})
    try:
        await es.indices.update_aliases(actions=alias_actions)
    except Exception:
        try:
            await es.indices.delete(index=new_name, ignore_unavailable=True)
        except Exception:
            pass
        raise
    if old_backing and old_backing != new_name:
        await es.indices.delete(index=old_backing, ignore_unavailable=True)
    return len(items)


async def _count_manifest() -> int:
    try:
        resp = await _es().count(index=INDEX_NUCLEI_TEMPLATES, ignore_unavailable=True)
        return int(resp.get("count", 0))
    except Exception:
        return 0


async def search_manifest(
    category: str | None = None,
    q: str | None = None,
    page: int = 1,
    size: int = 20,
) -> dict[str, Any]:
    """列表 + 搜索。q 在 name/template_id/path 上模糊匹配。

    列表只返回元数据（_source 排除 content），避免一次拉 13k 条大字段。
    索引未建时返回空（不 404）。
    """
    must: list[dict] = []
    if category:
        # 用 .keyword：category 是 text 字段，term/sort 在 text 上不可靠（分词）。
        must.append({"term": {"category.keyword": category}})
    if q:
        must.append(
            {
                "bool": {
                    "should": [
                        {"wildcard": {"name.keyword": {"value": f"*{q}*"}}},
                        {"wildcard": {"template_id.keyword": {"value": f"*{q}*"}}},
                        {"wildcard": {"path.keyword": {"value": f"*{q}*"}}},
                    ]
                }
            }
        )
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es = _es()
    try:
        # sort 必须用 .keyword：category/template_id 是 text，text 不能排序
        # （Fielddata disabled -> 400 -> 列表空）。列表排除 content 提速。
        resp = await es.search(
            index=INDEX_NUCLEI_TEMPLATES,
            query=query,
            sort=[{"category.keyword": "asc"}, {"template_id.keyword": "asc"}],
            from_=(page - 1) * size,
            size=size,
            source={"excludes": ["content"]},
            ignore_unavailable=True,
            allow_no_indices=True,
        )
    except Exception as exc:
        logger.warning("nuclei_templates_search_failed", error=str(exc))
        return {"items": [], "total": 0, "page": page, "size": size}
    total = resp.get("hits", {}).get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else 0
    items = [h["_source"] for h in resp["hits"]["hits"]]
    return {"items": items, "total": total_val, "page": page, "size": size}


async def get_template_doc(path: str) -> dict[str, Any] | None:
    """ES 取单条完整文档（含 content）。"""
    resp = await _es().get(index=INDEX_NUCLEI_TEMPLATES, id=path, ignore=[404])  # type: ignore[call-arg]
    if resp.get("found"):
        return resp["_source"]
    return None


async def upsert_template(item: TemplateMeta) -> None:
    """编辑保存后更新单条 ES 文档。"""
    await _es().index(index=INDEX_NUCLEI_TEMPLATES, id=item.path, document=item.doc(), refresh=True)


# --------------------------------------------------------------------- zip parsing


def _category_of(path: str) -> str:
    """顶层分类目录：cves/2024/x.yaml -> cves。无目录的归到 misc。"""
    parts = path.split("/")
    return parts[0] if len(parts) > 1 else "misc"


def _parse_yaml_meta(content: str) -> dict[str, Any]:
    """解析 nuclei 模板头部：id / info.name / info.severity / info.tags / info.author。

    解析失败时返回空 dict（仅丢失元数据，不影响 content 存储）。
    """
    try:
        import yaml

        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return {}
        info = doc.get("info") or {}
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif not isinstance(tags, list):
            tags = []
        return {
            "template_id": str(doc.get("id", "") or ""),
            "name": str(info.get("name", "") or ""),
            "severity": str(info.get("severity", "") or ""),
            "tags": [str(t) for t in tags],
            "author": str(info.get("author", "") or ""),
        }
    except Exception:
        return {}


def parse_templates_zip(zip_bytes: bytes, version: str = "") -> tuple[list[TemplateMeta], str]:
    """解析 nuclei-templates zip。

    剥掉顶层 ``nuclei-templates-<ver>/`` 目录，递归取所有 ``.yaml``/``.yml``，
    解析头部元数据；跳过无 ``id`` 的非模板 yaml（如 .pre-commit-config.yml）。
    返回 (items, detected_version)。detected_version 取自顶层目录名或回退传入 version。

    S-P1-6 (V12): rejects zip bombs -- total uncompressed size or entry count
    over the caps raise ValueError instead of inflating into memory.
    """
    detected = version
    items: list[TemplateMeta] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"invalid nuclei-templates zip: {exc}") from exc

    names = [n for n in zf.namelist() if not n.endswith("/")]
    if names:
        first = names[0].split("/")[0]
        m = re.search(r"nuclei-templates-(v?[\d.]+)", first)
        if m:
            detected = m.group(1).lstrip("v") or detected

    # Zip-bomb guards: 50k entries / 500MB uncompressed is far above any
    # real bundle (13k templates ~ 200MB) but rejects pathological archives.
    if len(zf.infolist()) > MAX_ZIP_ITEMS:
        raise ValueError(
            f"zip contains {len(zf.infolist())} entries, exceeds {MAX_ZIP_ITEMS} limit"
        )
    total_size = sum(i.file_size for i in zf.infolist())
    if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"zip uncompressed size {total_size} exceeds " f"{MAX_ZIP_UNCOMPRESSED_BYTES} limit"
        )

    for name in zf.namelist():
        if name.endswith("/") or name.startswith("__MACOSX"):
            continue
        if not (name.endswith(".yaml") or name.endswith(".yml")):
            continue
        parts = name.split("/", 1)
        rel = parts[1] if len(parts) > 1 else parts[0]
        rel = rel.lstrip("/")
        if not rel or rel.startswith("."):
            continue
        try:
            raw = zf.read(name).decode("utf-8", errors="replace")
        except Exception:
            continue
        meta = _parse_yaml_meta(raw)
        if not meta.get("template_id"):
            continue  # 非 nuclei 模板（无 id）
        items.append(
            TemplateMeta(
                path=rel,
                category=_category_of(rel),
                version=detected,
                content=raw,
                **meta,
            )
        )
    return items, detected


# --------------------------------------------------------------------- high-level ops


async def _ingest(items: list[TemplateMeta], version: str) -> dict[str, Any]:
    """重建 ES 索引 + 记版本 + 校对。推送前统计，推送后校对实际条数。

    Spec-P1-NUKE (V12): when the post-write ES count disagrees with the
    number of templates parsed, the drift is surfaced to operators (SSE
    event + audit log + matched=False in the response) instead of being
    silently logged -- a partial sync must never look like "13k templates
    synced" while search only finds 12k.
    """
    logger.info("nuclei_templates_sync_start", count=len(items), version=version)
    indexed = await rebuild_manifest(items)
    await _set_version(version)

    # Count right after refresh; ES may be briefly stale for 1s, so retry
    # once after a short wait before declaring a drift.
    actual = await _count_manifest()
    if actual < len(items):
        await asyncio.sleep(1)
        actual = await _count_manifest()
    matched = actual >= len(items)

    logger.info(
        "nuclei_templates_sync_done",
        version=version,
        expected=len(items),
        indexed=indexed,
        es_actual=actual,
        matched=matched,
    )
    if not matched:
        # Spec-P1-NUKE: surface partial sync so operators can investigate
        # (e.g. _id collisions, per-template parse drops) instead of seeing
        # "同步完成 N 条" while search returns fewer.
        await get_audit_logger().log(
            event_id="nuclei-templates",
            node="nuclei_templates.ingest",
            action="nuclei_templates_partial_sync",
            details={
                "version": version,
                "expected": len(items),
                "indexed": indexed,
                "es_actual": actual,
            },
        )
        try:
            await _redis().publish(
                "nuclei_templates:sync_drift",
                str(
                    {
                        "type": "nuclei_templates_sync_drift",
                        "version": version,
                        "expected": len(items),
                        "actual": actual,
                    }
                ),
            )
        except Exception:
            pass  # SSE drift event is best-effort; audit already recorded.

    return {
        "version": version,
        "count": len(items),
        "indexed": indexed,
        "es_actual": actual,
        "matched": matched,
    }


async def sync_from_mirror() -> dict[str, Any]:
    """联网更新：从内网下载站拉 nuclei-templates-{version}.zip 并入库 ES。"""
    if not await _acquire_sync_lock():
        raise RuntimeError("模板库同步正在进行中，请稍候再试")
    try:
        s = get_settings()
        base = (s.nuclei_download_base_url or "").strip().rstrip("/")
        version = (s.nuclei_templates_version or "").strip()
        if not base or not version:
            raise RuntimeError("NUCLEI_DOWNLOAD_BASE_URL / NUCLEI_TEMPLATES_VERSION 未配置")
        url = f"{base}/nuclei-templates-{version}.zip"
        async with httpx.AsyncClient(timeout=300.0, trust_env=False) as client:
            r = await client.get(url)
            if r.status_code != 200:
                raise RuntimeError(f"下载模板包失败: HTTP {r.status_code}")
            if len(r.content) > MAX_ZIP_UNCOMPRESSED_BYTES:
                # S-P1-6 (V12): an attacker-controlled mirror must not be
                # able to push an unbounded body into memory.
                raise RuntimeError(
                    f"下载的模板包 {len(r.content)} bytes 超过 "
                    f"{MAX_ZIP_UNCOMPRESSED_BYTES} 上限"
                )
            zip_bytes = r.content
        items, detected = parse_templates_zip(zip_bytes, version)
        if not items:
            raise RuntimeError("模板包解析为空")
        return await _ingest(items, detected or version)
    finally:
        await _release_sync_lock()


async def import_zip(file_bytes: bytes, filename: str = "") -> dict[str, Any]:
    """手动导入 zip：解析 + 版本校验 + 入库 ES。

    返回 {version, count, indexed, es_actual, matched, upgraded, previous_version}。
    upgraded = 导入版本比当前库版本新。
    """
    if not await _acquire_sync_lock():
        raise RuntimeError("模板库同步正在进行中，请稍候再试")
    try:
        s = get_settings()
        fallback_ver = (s.nuclei_templates_version or "").strip()
        items, detected = parse_templates_zip(file_bytes, fallback_ver)
        if not items:
            raise RuntimeError("模板包解析为空（未找到 .yaml）")
        cur = await current_version()
        upgraded = not cur or _version_gt(detected or fallback_ver, cur)
        result = await _ingest(items, detected or fallback_ver)
        result["upgraded"] = upgraded
        result["previous_version"] = cur
        return result
    finally:
        await _release_sync_lock()


def _version_gt(a: str, b: str) -> bool:
    """保守的版本比较：a > b。按数字段比较。"""
    an = [int(x) for x in re.findall(r"\d+", a)]
    bn = [int(x) for x in re.findall(r"\d+", b)]
    return an > bn


# --------------------------------------------------------------------- read / edit


async def list_templates(
    category: str | None = None, q: str | None = None, page: int = 1, size: int = 20
) -> dict[str, Any]:
    res = await search_manifest(category, q, page, size)
    res["version"] = await current_version()
    return res


async def get_template(path: str) -> dict[str, Any] | None:
    """详情：ES 取完整文档（元数据 + content）。"""
    return await get_template_doc(path)


async def save_template(path: str, content: str) -> dict[str, Any]:
    """编辑保存：重解析元数据 + 更新 ES 文档。不下发到 agent。

    S-P1-EDIT (V12): content must be valid nuclei YAML with an ``id`` --
    parse_templates_zip enforces the same contract on import, so the edit
    path can no longer store broken templates that nuclei silently skips.
    Raises ValueError (mapped to 422 by the router) on invalid YAML.
    """
    import yaml

    if not content.strip():
        raise ValueError("content 不能为空")
    try:
        parsed_yaml = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(parsed_yaml, dict) or not parsed_yaml.get("id"):
        raise ValueError("模板缺少 info.id 字段")
    existing = await get_template_doc(path)
    category = existing.get("category", _category_of(path)) if existing else _category_of(path)
    version = existing.get("version", "") if existing else ""
    parsed = _parse_yaml_meta(content)
    item = TemplateMeta(path=path, category=category, version=version, content=content, **parsed)
    await upsert_template(item)
    return {"ok": True, "path": path, **parsed}
