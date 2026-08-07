"""dpkg 风格版本比较（需求②: CPE→CVE 版本区间匹配）。

移植自 agent/internal/scan/matcher.go 的 compareVersions（服务端需要
一份，因为 agentless 扫描在服务端执行，不能依赖 Go agent 端实现）。

语义与 Debian dpkg 一致：
- 版本 = [epoch:]upstream[-revision]
- 交替比较非数字块（逐字符，'~' 排在一切之前含串尾）与数字块（数值
  比较，空块视为 0）
- 例：1.18.0-rc1 < 1.18.0；1:0.1 > 0.9；1.2.3-1 < 1.2.3-2

同时提供 CPE 版本规整（CPE 用 '_' 连接段、可能有 vendor 前缀差异）。
"""

from __future__ import annotations

import re

_EPOCH_RE = re.compile(r"^(\d+):")


def split_version(version: str) -> tuple[int, str, str]:
    """Split a version into (epoch, upstream, revision).

    ``"1:2.3.4-1.el9"`` -> ``(1, "2.3.4", "1.el9")``;
    ``"1.2.3"`` -> ``(0, "1.2.3", "")``.
    """
    v = version or ""
    epoch = 0
    m = _EPOCH_RE.match(v)
    if m:
        epoch = int(m.group(1))
        v = v[m.end():]
    upstream = v
    revision = ""
    if "-" in v:
        upstream, revision = v.split("-", 1)
    return epoch, upstream, revision


def _non_digit_prefix(s: str) -> int:
    i = 0
    while i < len(s) and not s[i].isdigit():
        i += 1
    return i


def _compare_non_digit(a: str, b: str) -> int:
    # dpkg: '~' sorts before everything, including end of string.
    i = j = 0
    while i < len(a) or j < len(b):
        ca = a[i] if i < len(a) else None
        cb = b[j] if j < len(b) else None
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1  # b has '~' -> b smaller
            if cb != "~":
                return -1  # a has '~' -> a smaller
            i += 1
            j += 1
            continue
        if ca is None:
            return -1
        if cb is None:
            return 1
        if ca != cb:
            return -1 if ca < cb else 1
        i += 1
        j += 1
    return 0


def _compare_digit(a: str, b: str) -> int:
    a = a.lstrip("0") or "0"
    b = b.lstrip("0") or "0"
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    if a != b:
        return -1 if a < b else 1
    return 0


def _compare_parts(a: str, b: str) -> int:
    """dpkg upstream/revision comparison: alternating chunks."""
    while len(a) > 0 or len(b) > 0:
        na = _non_digit_prefix(a)
        nb = _non_digit_prefix(b)
        if c := _compare_non_digit(a[:na], b[:nb]):
            return c
        a = a[na:]
        b = b[nb:]
        da = _digit_prefix_len(a)
        db = _digit_prefix_len(b)
        if c := _compare_digit(a[:da], b[:db]):
            return c
        a = a[da:]
        b = b[db:]
    return 0


def _digit_prefix_len(s: str) -> int:
    i = 0
    while i < len(s) and s[i].isdigit():
        i += 1
    return i


def compare_versions(a: str, b: str) -> int:
    """Compare two versions; negative if a < b, zero if equal, positive if a > b."""
    ea, ua, ra = split_version(a)
    eb, ub, rb = split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    if c := _compare_parts(ua, ub):
        return c
    return _compare_parts(ra, rb)


def version_matches(version: str, op: str, target: str) -> bool:
    """Check ``version op target``; ``op`` in {<, <=, =, >=, >, lt, le, eq, ge, gt}."""
    cmp = compare_versions(version, target)
    norm = op.lower()
    if norm in ("<", "lt"):
        return cmp < 0
    if norm in ("<=", "le"):
        return cmp <= 0
    if norm in ("=", "==", "eq"):
        return cmp == 0
    if norm in (">=", "ge"):
        return cmp >= 0
    if norm in (">", "gt"):
        return cmp > 0
    return False


def normalize_cpe_version(raw: str) -> str:
    """CPE 版本规整: CPE 2.3 用 ``_`` 连接段并可能有 ``*`` 通配。

    - ``1.2.3_1`` -> ``1.2.3-1``（underscore 视为 revision 分隔）;
    - ``1.2.3`` -> 原样;
    - ``*`` / 空 -> ``""``（调用方视为"任意版本"跳过区间匹配）。
    """
    if not raw or raw == "*":
        return ""
    v = raw.replace("_", "-")
    # 去掉多余前导 0 段? dpkg 比较已数值化处理, 无需。
    return v
