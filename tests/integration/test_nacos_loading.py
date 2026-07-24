"""Locks down the invariants of the Nacos config loading pipeline.

These tests are the regression guard for two related deployment bugs:
  1) Nacos override being suppressed by compose-injected env (the
     "127.0.0.1 forever" bug in single-host docker-compose setups).
  2) Nacos becoming unreachable inside the container because httpx
     inherits HTTP_PROXY/HTTPS_PROXY from the runtime image and tries
     to route http://127.0.0.1:8848 through it (the empty-error bug).

Each assertion carries a "Bug guard" comment so future contributors
know not to relax them.
"""

import os
import pytest

from src.common.config.nacos_loader import (
    PROTECTED_OVERRIDE_KEYS,
    _config_fingerprint,
    _format_exception,
    _make_client,
    _normalize_env_key,
    apply_nacos_overrides,
)


# --------------------------------------------------------------------- env helpers


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Strip well-known keys so each test starts from a clean baseline."""
    for key in (
        "PG_HOST", "REDIS_URL", "ES_HOSTS", "NACOS_SERVER",
        "API_SECRET_KEY", "AGENT_SIGNING_KEY", "AGENT_HMAC_KEY",
        "PG_PASSWORD", "NACOS_PASSWORD",
        "OPENAI_API_KEY",
        "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
        "NO_PROXY", "no_proxy",
    ):
        monkeypatch.delenv(key, raising=False)
    yield


def _settings_field_names() -> set:
    """Helper: lazily import Settings only after env is isolated."""
    from src.common.config.settings import Settings
    return set(Settings.model_fields.keys())


# --------------------------------------------------------------------- behavior tests


def test_address_keys_overridden_by_nacos():
    """Bug guard: docker-compose pinning 127.0.0.1 must NOT silence Nacos."""
    os.environ["PG_HOST"] = "127.0.0.1"
    summary = apply_nacos_overrides({"pg_host": "10.0.0.50"})
    assert os.environ["PG_HOST"] == "10.0.0.50", (
        "Nacos address update was suppressed by compose-injected env; "
        "Nacos must own service addresses for new deployments to work."
    )
    assert "PG_HOST" in summary["applied"]


def test_signing_keys_protected_from_nacos():
    """Bug guard: Nacos must not silently replace JWT signing material."""
    os.environ["API_SECRET_KEY"] = "ci-injected-key-32-bytes-min-len!"
    summary = apply_nacos_overrides({"API_SECRET_KEY": "nacos-attacker-key"})
    assert os.environ["API_SECRET_KEY"] == "ci-injected-key-32-bytes-min-len!"
    assert "API_SECRET_KEY" in summary["skipped_protected"]


def test_signing_keys_skipped_only_when_already_present():
    """Bootstrapping path: if CI did NOT inject the key, Nacos may seed it."""
    summary = apply_nacos_overrides({"API_SECRET_KEY": "first-time-bootstrap-key-1234567890ab"})
    assert os.environ["API_SECRET_KEY"] == "first-time-bootstrap-key-1234567890ab"
    assert "API_SECRET_KEY" in summary["applied"]
    assert "API_SECRET_KEY" not in summary["skipped_protected"]


def test_pg_password_protected():
    """Bug guard: CI-injected DB password wins over Nacos."""
    os.environ["PG_PASSWORD"] = "ci-secret"
    apply_nacos_overrides({"PG_PASSWORD": "nacos-leaked"})
    assert os.environ["PG_PASSWORD"] == "ci-secret"


def test_camelcase_keys_normalized():
    """Bug guard: nacos-config.yaml style `pgHost` must map to PG_HOST in env."""
    valid = _settings_field_names()
    canonical = _normalize_env_key("pgHost", valid)
    assert canonical == "pg_host"
    apply_nacos_overrides({"pgHost": "10.0.0.60"})
    assert os.environ["PG_HOST"] == "10.0.0.60"


def test_dashed_keys_normalized():
    """Bug guard: nacos-config.yaml style `pg-host` must map to pg_host canonical."""
    valid = _settings_field_names()
    canonical = _normalize_env_key("pg-host", valid)
    assert canonical == "pg_host"
    apply_nacos_overrides({"pg-host": "10.0.0.61"})
    assert os.environ["PG_HOST"] == "10.0.0.61"


def test_already_uppercase_keys_pass_through():
    """Bug guard: most common Nacos yaml style still works."""
    valid = _settings_field_names()
    canonical = _normalize_env_key("PG_HOST", valid)
    assert canonical == "pg_host"


def test_none_values_skipped():
    """Bug guard: nacos-config.yaml `key: null` does not blank out env."""
    os.environ["ES_HOSTS"] = "http://preset-host:9200"
    summary = apply_nacos_overrides({"ES_HOSTS": None})
    assert os.environ["ES_HOSTS"] == "http://preset-host:9200"
    assert "ES_HOSTS" not in summary["applied"]


def test_unknown_keys_still_written_and_flagged():
    """Bug guard: typo in nacos-config.yaml does not crash; it warns."""
    summary = apply_nacos_overrides({"KAFKAA_BROKER": "10.0.0.7"})  # typo: extra A
    assert os.environ.get("KAFKAA_BROKER") == "10.0.0.7"
    assert "KAFKAA_BROKER" in summary["unrecognized"]


def test_fingerprint_stable_for_same_content():
    """Bug guard: same Nacos content must produce same hash."""
    a = {"pg_host": "10.0.0.1", "es_hosts": "http://10.0.0.2:9200"}
    b = {"es_hosts": "http://10.0.0.2:9200", "pg_host": "10.0.0.1"}
    assert _config_fingerprint(a) == _config_fingerprint(b)


def test_fingerprint_changes_on_value_change():
    """Bug guard: a config edit produces a different hash."""
    before = _config_fingerprint({"pg_host": "10.0.0.1"})
    after = _config_fingerprint({"pg_host": "10.0.0.2"})
    assert before != after


def test_protected_whitelist_includes_credentials_not_addresses():
    """Static guard against regressions: whitelist must be small + targeted."""
    assert "PG_HOST" not in PROTECTED_OVERRIDE_KEYS
    assert "REDIS_URL" not in PROTECTED_OVERRIDE_KEYS
    assert "ES_HOSTS" not in PROTECTED_OVERRIDE_KEYS
    for cred in (
        "API_SECRET_KEY",
        "AGENT_SIGNING_KEY",
        "AGENT_HMAC_KEY",
        "PG_PASSWORD",
        "NACOS_PASSWORD",
    ):
        assert cred in PROTECTED_OVERRIDE_KEYS, f"{cred} must be in the whitelist"


def test_whitelist_keys_are_uppercase():
    """Static guard: PROTECTED_OVERRIDE_KEYS must all be uppercase."""
    for k in PROTECTED_OVERRIDE_KEYS:
        assert k == k.upper(), f"{k!r} is not uppercase"


# --------------------------------------------------------------------- proxy bypass tests


def test_make_client_disables_proxy_trust(monkeypatch):
    """Bug guard: Nacos httpx client must NEVER trust HTTP_PROXY/HTTPS_PROXY.

    Regression test for the case where the runtime container inherits
    HTTP_PROXY/HTTPS_PROXY (e.g. from `docker build --build-arg
    HTTPS_PROXY=...`), httpx with trust_env=True routes a call to
    http://127.0.0.1:8848 through the proxy, and the connection fails with
    an opaque empty error.

    Even if a future deployment genuinely needs an HTTP proxy for Nacos,
    that should be configured explicitly via a dedicated flag, not via
    the global env, so this bug cannot recur silently.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://192.168.254.121:7897")
    monkeypatch.setenv("HTTPS_PROXY", "http://192.168.254.121:7897")
    monkeypatch.setenv("http_proxy", "http://192.168.254.121:7897")
    monkeypatch.setenv("https_proxy", "http://192.168.254.121:7897")

    client = _make_client()
    try:
        assert client.trust_env is False, (
            "Nacos httpx client must disable proxy trust; otherwise the "
            "loopback URL gets routed through the container's HTTP_PROXY."
        )
    finally:
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(client.aclose())
        finally:
            loop.close()


def test_format_exception_fills_empty_string():
    """Bug guard: empty str(exc) must NOT cause logs to swallow the failure.

    httpx 0.27.x in some proxy-routing scenarios raises an exception whose
    str() is the empty string. The previous code logged exactly that, so
    operators saw `{"error": "", "event": "nacos_config_unavailable"}` and
    had no idea what went wrong. _format_exception must always emit
    something actionable.
    """

    class _SilentException(Exception):
        def __str__(self):
            return ""

    info = _format_exception(_SilentException())
    assert info["error"] != "", "error must not be empty even for Sphinx-like excs"
    assert info["error_type"] == "_SilentException"
    assert "_SilentException" in info["error_repr"]


def test_format_exception_uses_str_when_available():
    """Bug guard: when str(exc) IS informative, prefer it for the error field."""
    info = _format_exception(ValueError("api secret too short"))
    assert info["error"] == "api secret too short"
    assert info["error_type"] == "ValueError"
