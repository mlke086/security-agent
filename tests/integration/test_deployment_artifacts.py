"""Static regression guards for deployment artifacts.

These tests parse configuration files (`Dockerfile.api`, `docker-compose.yml`,
`nacos-config.yaml`) and assert safety invariants that are easier to enforce
this way than to discover at runtime. Each test names the bug it prevents
so future contributors know not to relax it.
"""

import pathlib
import re

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEPLOYMENTS = REPO_ROOT / "deployments" / "prod"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _dockerfile_section(dockerfile: str, start_marker: str, end_marker: str | None) -> str:
    """Return the slice of a multi-stage Dockerfile between two markers.

    Used by tests that need to scope assertions to a single stage -- the
    builder stage legitimately sets proxy env vars; the runtime stage must NOT.
    """
    start = dockerfile.find(start_marker)
    if start == -1:
        return dockerfile
    body = dockerfile[start + len(start_marker):]
    if end_marker:
        end = body.find(end_marker)
        if end == -1:
            return body
        return body[:end]
    return body


def _strip_shell_comments(text: str) -> str:
    """Drop `# ...` comments that could otherwise trip substring checks.

    A naive substring test like `assert "ENV http_proxy" not in section`
    would fire on a documentation comment that says "never add ENV
    http_proxy". Join continuation lines (BACKSLASH newline) so a single
    `ENV http_proxy=...` directive is matched as one logical line.
    """
    no_comments = "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("#")
    )
    joined = re.sub(r"\\\n\s*", " ", no_comments)  # join continuation lines
    return joined


# --------------------------------------------------------------------------- runtime leak guards


def test_runtime_stage_does_not_leak_proxy_env():
    """Bug guard: `Dockerfile.api` runtime stage must not bake proxy env into the image layer.

    The original Dockerfile forwarded `HTTP_PROXY` / `HTTPS_PROXY` build args
    into the runtime stage's `ENV http_proxy=...` / `https_proxy=...`. When
    the operator passes `--build-arg HTTPS_PROXY=...`, the runtime image
    then carries those env vars into every container process. httpx (and
    any other library that respects `trust_env=True`) routes loopback calls
    through the build proxy, where 127.0.0.1 is unreachable. The deployment
    ends up logging `nacos_config_unavailable error=""` despite Nacos
    being reachable from the host.

    The fix is structural: keep proxy env in the builder stage only. The
    runtime layer must run clean.
    """
    dockerfile = _read(DEPLOYMENTS / "docker" / "Dockerfile.api")
    runtime_raw = _dockerfile_section(dockerfile, "AS runtime", None)
    runtime_clean = _strip_shell_comments(runtime_raw)

    # Build a regex anchored to the start of a directive (after whitespace),
    # so comment text like 'Never add `ENV http_proxy` back' can't trip it.
    forbidden_pattern = re.compile(
        r"^\s*ENV\s+(?:[A-Z_][A-Z0-9_]*\s+)*(?P<key>http_proxy|https_proxy|no_proxy|HTTP_PROXY|HTTPS_PROXY|NO_PROXY)\s*[=:]",
        re.MULTILINE,
    )
    matches = list(forbidden_pattern.finditer(runtime_clean))
    assert not matches, (
        "Build-time proxy env vars must not appear in the runtime stage. "
        f"Found: {[m.group(0).strip() for m in matches]}. Keeping them "
        "leaks build-time proxy routing into every container process and "
        "breaks loopback connections (Nacos / PG / Redis / ES)."
    )


def test_runtime_stage_does_not_declare_proxy_build_args():
    """Bug guard: builder-only ARGs must not be declared in runtime stage.

    `ARG HTTP_PROXY=""` and `ARG HTTPS_PROXY=""` belong to the builder
    stage for pip / apt. Re-declaring them in the runtime stage brings
    them back into scope and tempts a future contributor to add ENV lines
    that re-leak them. Strip both ARGs from the runtime stage entirely.
    """
    dockerfile = _read(DEPLOYMENTS / "docker" / "Dockerfile.api")
    runtime_raw = _dockerfile_section(dockerfile, "AS runtime", None)
    runtime_clean = _strip_shell_comments(runtime_raw)

    forbidden_args = re.compile(r"^\s*ARG\s+(HTTP_PROXY|HTTPS_PROXY|NO_PROXY)\b", re.MULTILINE)
    matches = list(forbidden_args.finditer(runtime_clean))
    assert not matches, (
        "Builder-only ARGs leaked into runtime stage: "
        f"{[m.group(0).strip() for m in matches]}. Strip them -- the "
        "runtime image should be proxy-arg-free."
    )


# --------------------------------------------------------------------------- builder presence guards


def test_builder_stage_still_uses_proxy_args():
    """Bug guard: builder stage must keep proxy args (regression on the fix).

    A drive-by cleanup could delete the builder-stage proxy ARGs while
    refactoring. The build still legitimately needs them to pull pypi /
    Debian packages across the corporate proxy. Assert they remain.
    """
    dockerfile = _read(DEPLOYMENTS / "docker" / "Dockerfile.api")
    builder_raw = _dockerfile_section(dockerfile, "AS builder", "AS runtime")
    builder_clean = _strip_shell_comments(builder_raw)

    assert re.search(r"^\s*ARG\s+HTTP_PROXY\b", builder_clean, re.MULTILINE), (
        "builder stage must declare `ARG HTTP_PROXY` so pip / apt can "
        "reach PyPI / Debian mirrors through the corporate proxy."
    )
    # After joining continuation lines, an ENV directive like
    # `ENV PIP_INDEX_URL=... http_proxy=${HTTP_PROXY} ...` collapses to a
    # single line containing both `http_proxy=` and `https_proxy=`. Just
    # assert those substrings are present; the format specifics live in
    # the rest of the test suite that exercises the build itself.
    assert "http_proxy=" in builder_clean, (
        "builder stage must set `http_proxy=` so pip / apt can reach "
        "external mirrors through the build-time proxy."
    )
    assert "https_proxy=" in builder_clean, (
        "builder stage must set `https_proxy=` for HTTPS-only pypi mirrors."
    )


def test_dockerfile_no_proxy_in_builder_resolves_correctly():
    """Bug guard: builder stage must tell apt / pip to skip localhost via no_proxy."""
    dockerfile = _read(DEPLOYMENTS / "docker" / "Dockerfile.api")
    builder_raw = _dockerfile_section(dockerfile, "AS builder", "AS runtime")
    builder_clean = _strip_shell_comments(builder_raw)

    assert re.search(r"\bno_proxy\b", builder_clean), (
        "builder stage must set `no_proxy` so 127.0.0.1 (e.g. cache, "
        "DNS, apt mirror) stays direct even when the corporate proxy "
        "is in scope."
    )


# --------------------------------------------------------------------------- nacos client guard


def test_dockerfile_frontend_runtime_does_not_leak_proxy_env():
    """Bug guard: frontend runtime is independent (nginx:alpine) and must not carry proxy env.

    The frontend image's runtime stage comes from `nginx:alpine`, a totally
    separate base -- it does not inherit proxy env. As a defense, ensure no
    contributor accidentally re-introduces `ENV http_proxy` in the runtime
    stage here either.
    """
    dockerfile = _read(DEPLOYMENTS / "docker" / "Dockerfile.frontend")
    runtime_raw = _dockerfile_section(dockerfile, "AS runtime", None)
    runtime_clean = _strip_shell_comments(runtime_raw)

    forbidden = re.compile(
        r"^\s*ENV\s+(?:[A-Z_][A-Z0-9_]*\s+)*(?P<key>http_proxy|https_proxy|no_proxy)\s*[=:]",
        re.MULTILINE | re.IGNORECASE,
    )
    assert not list(forbidden.finditer(runtime_clean)), (
        "frontend runtime stage must not bake proxy env vars. nginx:alpine "
        "should serve traffic direct, not via the corporate proxy."
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
