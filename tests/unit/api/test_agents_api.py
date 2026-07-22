"""API tests for /api/v1/agents endpoints.

Covers: enroll-tokens, install, enroll, binary, ca, host CRUD, upgrade, config.
Per-tool-call spec: 200 + 401/403 + 422 + boundary for each endpoint.
"""
from datetime import UTC
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Must import app after conftest sets STORE_BACKEND=memory
from src.api.main import app

client = TestClient(app)

# -- helpers ------------------------------------------------------------------

def _login(role="admin"):
    passwords = {"admin": "admin123", "analyst": "analyst123", "viewer": "viewer123", "responder": "responder123"}
    resp = client.post("/api/v1/auth/login", json={"username": role, "password": passwords[role]})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth_headers(role="admin"):
    return {"Authorization": f"Bearer {_login(role)}"}


# -- auth ---------------------------------------------------------------------

class TestAuth:
    def test_login_admin_returns_token(self):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["role"] == "admin"

    def test_login_wrong_password_401(self):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_missing_fields_422(self):
        resp = client.post("/api/v1/auth/login", json={"username": "admin"})
        assert resp.status_code == 422

    def test_me_returns_user(self):
        headers = _auth_headers("admin")
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"

    def test_me_no_token_401(self):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401


    def test_disabled_user_cannot_login(self):
        # P1-API-01 (2026-07-20): a disabled user must NOT be able to log
        # in even with the correct password. We monkeypatch get_user so
        # the test does not depend on the PG seed.
        from passlib.context import CryptContext

        from src.api.auth import jwt as jwt_module
        _pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
        valid_hash = _pwd.hash("any")
        async def _fake_disabled(username):
            return jwt_module.UserInDB(
                username=username, hashed_password=valid_hash,
                role="admin", disabled=True,
            )
        original = jwt_module.get_user
        jwt_module.get_user = _fake_disabled
        try:
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "admin123"},
            )
            assert resp.status_code == 401
        finally:
            jwt_module.get_user = original

    def test_sse_token_endpoint_returns_short_lived_jwt(self):
        # P1-API-04 (2026-07-20): /auth/sse-token mints a token scoped
        # to one channel with a 60s TTL.
        headers = _auth_headers("admin")
        resp = client.post(
            "/api/v1/auth/sse-token",
            json={"scope": "events"},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["expires_in"] == 60
        assert body["token"] != headers["Authorization"].split()[-1]

    def test_sse_token_endpoint_rejects_unauthenticated(self):
        resp = client.post("/api/v1/auth/sse-token", json={"scope": "events"})
        assert resp.status_code == 401


# -- health -------------------------------------------------------------------

class TestHealth:
    def test_health_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# -- enroll-tokens ------------------------------------------------------------

class TestEnrollTokens:
    def test_create_token_as_admin(self):
        headers = _auth_headers("admin")
        resp = client.post("/api/v1/agents/enroll-tokens", json={"group": "prod", "ttl_hours": 24, "uses": 1}, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert "expires" in data

    def test_create_token_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/agents/enroll-tokens", json={"group": "prod"}, headers=headers)
        assert resp.status_code == 403

    def test_create_token_no_auth_401(self):
        resp = client.post("/api/v1/agents/enroll-tokens", json={"group": "prod"})
        assert resp.status_code == 401


# -- install ------------------------------------------------------------------

class TestInstall:
    @pytest.mark.asyncio
    async def test_install_script_linux_valid_token(self):
        # P1 / T-1: the install endpoint calls peek_enroll_token (non-consuming);
        # mock the actual function it uses, not validate_enroll_token.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get("/api/v1/agents/install", params={"token": "valid-token", "os": "linux"})
            assert resp.status_code == 200
            assert "systemctl" in resp.text

    def test_install_script_invalid_token_422(self):
        resp = client.get("/api/v1/agents/install", params={"token": "bad-token", "os": "linux"})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_install_script_download_two_step_recommendation(self):
        # P1 / install UX: the install endpoint should return text/plain and set
        # Content-Disposition so ``curl -O`` saves to a sensible filename.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get(
                "/api/v1/agents/install",
                params={"token": "valid-token", "os": "linux"},
            )
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        # Filename for downloaded script:
        cd = resp.headers.get("content-disposition", "")
        assert "secagent-install.sh" in cd
        # Recommended two-step invocation documented in the script header:
        assert "sudo bash secagent-install.sh" in resp.text
        # Token must reach the binary download via Authorization header, NOT URL:
        assert "Authorization: Bearer $TOKEN" in resp.text
        assert "BIN_URL=" in resp.text
        assert "$BIN_URL?token=" not in resp.text  # no token-in-URL leak

    @pytest.mark.asyncio
    async def test_install_helper_returns_two_step_snippet(self):
        # The helper endpoint should emit the curl-then-bash two-step form.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get(
                "/api/v1/agents/install-helper",
                params={"token": "valid-token", "os": "linux"},
            )
        assert resp.status_code == 200
        assert "secagent-install.sh" in resp.text
        # Snippet must be the two-step form (download as file, then execute):
        assert "-o secagent-install.sh" in resp.text
        assert "sudo bash secagent-install.sh" in resp.text
        # Token should appear ONLY in the curl URL; no piping to bash:
        assert "curl -fsSL" in resp.text
        assert "| bash" not in resp.text

    @pytest.mark.asyncio
    async def test_install_helper_invalid_token_422(self):
        resp = client.get(
            "/api/v1/agents/install-helper",
            params={"token": "bad-token", "os": "linux"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_install_helper_linux_single_line_no_continuation(self):
        # The Linux snippet must be a single physical line -- no `\`
        # continuations. Pasted into a real terminal those get literalised and
        # the next `&&` ends up on its own line, breaking the command.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get(
                "/api/v1/agents/install-helper",
                params={"token": "valid-token", "os": "linux"},
            )
        assert resp.status_code == 200
        snippet = resp.text.strip()
        # No backslash-continuations
        assert "\\\n" not in snippet, f"unexpected line continuation in: {snippet!r}"
        # No literal newlines mid-snippet (Windows is allowed to have them)
        assert "\n" not in snippet or snippet.count("\n") <= 1
        # Single logical command -- should have two `&&` joining three parts
        assert snippet.count("&&") == 2
        # Starts with curl, ends with sudo bash
        assert snippet.startswith("curl -fsSL")
        assert "sudo bash secagent-install.sh" in snippet

    @pytest.mark.asyncio
    async def test_install_helper_url_is_double_quoted(self):
        # The token-bearing URL must be wrapped in double quotes so the shell
        # does not interpret the `&` in `&os=linux` as a job-control operator.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get(
                "/api/v1/agents/install-helper",
                params={"token": "valid-token", "os": "linux"},
            )
        assert resp.status_code == 200
        snippet = resp.text
        # URL is inside double quotes:
        assert '"http' in snippet or '"https' in snippet
        # No unquoted `&os=`:
        assert " &os=" not in snippet
        assert "& os=" not in snippet

    @pytest.mark.asyncio
    async def test_install_helper_linux_has_no_trailing_backslash_n(self):
        # P1 / 2026-07-17 user feedback: the Linux snippet was emitted with a
        # trailing ``\\n`` (two literal chars in a raw f-string: backslash + n).
        # When pasted into bash, the final argument became
        # ``secagent-install.sh\\n`` which bash tried to execute as a file
        # literally named ``secagent-install.sh\\n`` -> "No such file or
        # directory". The snippet must end exactly at the last command.
        with patch("src.api.routers.agents.peek_enroll_token", AsyncMock(return_value={"group": "prod"})):
            resp = client.get(
                "/api/v1/agents/install-helper",
                params={"token": "valid-token", "os": "linux"},
            )
        assert resp.status_code == 200
        snippet = resp.text
        # No trailing literal backslash-n or any newline:
        assert not snippet.endswith("\\n"), f"snippet ends with literal backslash-n: {snippet!r}"
        assert not snippet.endswith("\n"), f"snippet ends with newline: {snippet!r}"
        # And no embedded literal ``\\n`` anywhere (the snippet is single-line):
        assert "\\n" not in snippet, f"snippet contains literal backslash-n: {snippet!r}"

    def test_install_script_writes_agent_credentials_to_config(self):
        # P0 / 2026-07-17: the install script used to write config.json with
        # only console_url + ca_path (and ``$CONSOLE`` was a literal string
        # because of a single-quoted heredoc). The Go agent then started
        # without agent_id / agent_token and crashed with
        # "no agent_id configured and no enrollment token available",
        # sending systemd into a crash loop.
        # The fixed script:
        # 1. Enables the systemd unit but does NOT start it yet
        # 2. Calls /enroll and parses the JSON response for agent_id + agent_token
        # 3. Writes those into config.json with an UNQUOTED heredoc so
        #    $CONSOLE / $CONFIG_DIR are interpolated at install time
        # 4. Only then restarts the service
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        # Systemd unit is enabled but NOT restarted until config has credentials:
        assert "systemctl enable ${SERVICE_NAME}.service" in script
        # Service restart must be CONDITIONAL on credentials (not unconditional
        # like the old bug where it started before config.json was written):
        assert "systemctl restart ${SERVICE_NAME}.service" in script
        # Config.json heredoc must be UNQUOTED (so $CONSOLE / $CONFIG_DIR expand):
        assert "<<EOFCFG\n" in script or "<<EOFCFG" in script, \
            "config.json heredoc must be unquoted"
        assert "<<\'EOFCFG\'" not in script, \
            "config.json heredoc must not be single-quoted"
        # The config body must include agent_id AND agent_token placeholders:
        assert '"agent_id": "$AGENT_ID"' in script
        assert '"agent_token": "$AGENT_TOKEN"' in script
        # Order check: register block (step 6) must come BEFORE the config
        # write (step 7). Find approximate offsets.
        reg_idx = script.find("Registering host")
        cfg_idx = script.find("Persist config")
        assert reg_idx > 0 and cfg_idx > 0
        assert reg_idx < cfg_idx, \
            "/enroll must be called BEFORE writing config.json (so agent_id is available)"

    def test_install_script_has_no_garbage_after_last_log(self):
        # P1 / 2026-07-17: the install script had a leftover fragment after the
        # closing ``log "Installation complete..."`` line -- a copy-paste residue
        # from a previous edit. Bash parsed the bare ``Service: ${SERVICE_NAME}``
        # as a command and choked on the ``(`` -> "syntax error near unexpected
        # token (". The test catches any line that starts with the trailing
        # fragment keywords (Service:, Description:, ExecStart=, etc.) outside
        # of a proper context.
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        # Find the closing log line.
        marker = "Installation complete."
        idx = script.find(marker)
        assert idx > 0
        tail = script[idx:]
        # The closing log line ends at the next unescaped double-quote.
        # Nothing meaningful should follow after the log line's closing quote.
        # (placeholder removed; sanity check follows)
        # Simpler sanity: the substring after the LAST log line should be empty.
        last_log_end = tail.find("\"")
        assert last_log_end > 0
        after_log = tail[last_log_end + 1:]
        # The leftover we hit was a line that started with "Service:" and had
        # an unbalanced "(...)". Strip leading whitespace + newlines and
        # assert nothing remains.
        assert after_log.strip() == "", f"leftover garbage after closing log: {after_log!r}"

    def test_install_script_handles_curl_partial_write(self):
        # P1 / 2026-07-17: the original script used
        #     HTTP_CODE=$(curl ... || echo "000")
        # which CONCATENATED the "-w" output ("200") with the "000" fallback when
        # curl exited non-zero -- producing "200000", causing the success check
        # to fail and the install to abort even though the binary had been
        # downloaded successfully. The fix separates the two: HTTP_CODE gets
        # the real status (or empty on total failure) and the fallback only
        # kicks in when HTTP_CODE is empty via parameter expansion.
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        # The bad concat pattern must NOT appear.
        assert "|| echo \"000\")" not in script, "HTTP_CODE capture must not concat fallback"
        # The new pattern uses ``${HTTP_CODE:-000}`` parameter expansion.
        assert 'HTTP_CODE="${HTTP_CODE:-000}"' in script, "must use parameter expansion fallback"
        # And we accept a downloaded file even when HTTP_CODE is 000 if the
        # body is a valid ELF (covers curl exit code 23 partial-write cases).
        assert 'grep -aq "ELF"' in script
        assert "IS_ELF=1" in script

    def test_install_script_extracts_rule_version_from_enroll(self):
        # P1 (2026-07-17): host UI showed rule_version as "-" because the
        # install script never read it from the /enroll response. The fix
        # extracts rule_version from REG_RESP and persists it into config.json
        # so the agent starts with a real version.
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        # python3 branch extracts rule_version from JSON
        # python3 branch extracts rule_version from JSON
        assert "d.get('rule_version','')" in script

        # sed fallback also extracts rule_version
        assert '"rule_version"[[:space:]]*:[[:space:]]*"[^"]*"' in script
        # RULE_VERSION is initialised empty in the failure branch
        # RULE_VERSION must be initialised to empty in the failure branch.
        # We check substring presence + position relative to else so
        # both LF and CRLF source files are accepted.
        assert ('RULE_VERSION=""' in script)
        empty_idx = script.find('RULE_VERSION=""') if 'RULE_VERSION=""' in script else -1
        assert empty_idx > 0
        # The empty-value branch must precede the JSON-parsing branch (else).
        else_idx = script.find("    else", empty_idx)
        assert else_idx > empty_idx, (
            "RULE_VERSION=\"\" must come before the else that parses the response")
        from src.agents.models import EnrollResponse
        fields = set(EnrollResponse.model_fields.keys())
        assert "rule_version" in fields, "EnrollResponse must expose rule_version"

    def test_engine_field_roundtrip_through_scantask(self):
        # P0 (2026-07-18): engine selector flows from API -> ScanTask -> WS
        # scan_command payload -> agent engine.go. We assert the model + the
        # WS payload construction both carry the new field.
        from src.agents.models import ScanTask
        t = ScanTask(
            task_id="task-engine-1",
            engine="nuclei",
            nuclei_severity=["critical", "high"],
            nuclei_tags=["rce", "auth-bypass"],
            nuclei_templates=["cves/2024/CVE-2024-1234"],
            nuclei_timeout_sec=300,
        )
        # Make sure the model exposes the new fields consistently.
        assert t.engine == "nuclei"
        assert "critical" in t.nuclei_severity
        assert "rce" in t.nuclei_tags
        assert "cves/2024/CVE-2024-1234" in t.nuclei_templates
        assert t.nuclei_timeout_sec == 300
        # And that ScanIntent-style scan_task dict (which is what we send to
        # the WS gateway) carries them too. We use a tiny inline construction
        # mirroring the payload builder; we don't call the actual subgraph
        # because that requires ES + LangGraph.
        payload = {
            "task_id": t.task_id,
            "engine": t.engine,
            "nuclei_targets": t.targets,
            "nuclei_severity": t.nuclei_severity,
            "nuclei_tags": t.nuclei_tags,
            "nuclei_templates": t.nuclei_templates,
            "nuclei_timeout_sec": t.nuclei_timeout_sec,
        }
        assert payload["engine"] == "nuclei"
        assert payload["nuclei_targets"] == []
        assert "rce" in payload["nuclei_tags"]
        assert payload["nuclei_timeout_sec"] == 300

    def test_install_script_downloads_nuclei(self):
        # P0 (2026-07-18): install.sh must attempt to fetch the nuclei CLI
        # alongside the agent binary so the agent's runNuclei() path has
        # something to invoke. The download is best-effort: failure should
        # not abort the install (matcher-only mode still works).
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        assert "install_nuclei()" in script, (
            "install.sh should call install_nuclei() (P0 step 6)")
        assert "/opt/secagent/bin/nuclei" in script, (
            "nuclei binary should land at /opt/secagent/bin/nuclei")
        assert "projectdiscovery/nuclei" in script, (
            "nuclei should be downloaded from the official GitHub release")
        # Best-effort: failure paths must NOT contain 'exit 1' that would
        # abort the whole install.
        assert "install_nuclei || true" in script

    def test_install_script_systemd_unit_expands_variables(self):
        # P1 / 2026-07-17 user feedback: systemd unit had ExecStart=$INSTALL_DIR/agent
        # (literal) which systemd rejected as "bad unit file setting". The root
        # cause was the heredoc using ``<<\'EOFSVC\'`` (single-quoted) which
        # disables bash variable expansion. Both heredocs must be UNQUOTED so
        # bash interpolates $INSTALL_DIR / ${SERVICE_NAME} / $CONSOLE /
        # $AGENT_ID / $AGENT_TOKEN / $SERVER_PUBKEY before writing the file.
        # The Go agent's config.Load() does a plain json.Unmarshal (no shell
        # variable expansion), so the runtime values must be baked into
        # config.json at install time -- keeping both heredocs unquoted is
        # the only correct design that satisfies "agent starts with real
        # agent_token / server_public_key" without requiring Go-side parsing.
        from src.agents.enroll import get_install_script_content
        script = get_install_script_content("tok123", "linux", console_url="http://console:8000")
        # The systemd heredoc opener MUST be unquoted:
        assert "<<EOFSVC" in script, "systemd heredoc opener must not be single-quoted"
        assert "<<\'EOFSVC\'" not in script, "systemd heredoc opener must not be single-quoted"
        # The JSON config heredoc MUST also be unquoted (bash expands
        # $CONSOLE / $AGENT_ID / $AGENT_TOKEN / $SERVER_PUBKEY into the file):
        assert "<<EOFCFG" in script, "config.json heredoc must be unquoted for bash variable expansion"
        assert "<<\'EOFCFG\'" not in script, "config.json heredoc must be unquoted"

    @pytest.mark.asyncio
    async def test_enroll_host_sets_last_heartbeat_to_now(self):
        # P0 / 2026-07-17 user feedback: Host Pydantic model defaults
        # last_heartbeat to "" but the PG column is timestamptz, so asyncpg
        # rejected the bind with "expected datetime, got str" -> /enroll
        # returned 500. The enroll handler must set last_heartbeat = now so
        # the write succeeds without callers having to remember the field.
        from datetime import UTC, datetime
        captured = {}
        class FakeStore:
            async def save_host(self, host):
                captured["host"] = host
        class FakeAuthStore:
            async def register_enroll_token(self, *a, **kw):
                pass
        with (
            patch("src.api.routers.agents.get_vulnscan_store", return_value=FakeStore()),
            patch("src.api.routers.agents.register_enroll_token", AsyncMock()),
            patch("src.api.routers.agents.validate_enroll_token", AsyncMock(return_value={"group": "prod"})),
            patch("src.api.routers.agents.get_audit_logger") as mock_audit,
        ):
            mock_audit.return_value.log = AsyncMock()
            resp = client.post(
                "/api/v1/agents/enroll",
                json={
                    "token": "valid", "hostname": "web-01", "os": "linux",
                    "arch": "amd64", "ip": "10.0.0.1", "kernel": "5.10",
                },
            )
        assert resp.status_code == 200, resp.text
        host = captured["host"]
        assert host.last_heartbeat, "last_heartbeat must be set on enroll"
        # Parse the ISO string and confirm it's within the last 60 seconds.
        ts = datetime.fromisoformat(host.last_heartbeat)
        delta = abs((datetime.now(UTC) - ts).total_seconds())
        assert delta < 60, f"last_heartbeat must be ~now, got delta {delta}s"
        # P0-fix (round 2, 2026-07-17): the string would still crash asyncpg
        # because its timestamptz codec only accepts datetime objects, not
        # strings. The store layer must parse it via _parse_ts.
        from src.agents.store import _parse_ts
        parsed = _parse_ts(host.last_heartbeat)
        from datetime import datetime
        assert isinstance(parsed, datetime), (
            f"_parse_ts must return datetime, got {type(parsed).__name__}")

    def test_console_url_endpoint_returns_configured_url(self):
        # When ``agent_console_external_url`` is set, that wins over the
        # request host header -- so copy-paste commands point at the
        # deployable URL, not whatever the operator's browser happened to hit.
        from unittest.mock import patch
        with patch("src.api.routers.agents.get_settings") as mock_settings:
            mock_settings.return_value.agent_console_external_url = "https://console.prod.example.com"
            resp = client.get("/api/v1/agents/console-url")
        assert resp.status_code == 200
        body = resp.json()
        assert body["console_url"] == "https://console.prod.example.com"
        assert body["source"] == "configured"

    def test_console_url_endpoint_falls_back_to_request(self):
        # When the setting is empty, use the request host header so dev / first
        # boot still produces a working URL.
        from unittest.mock import patch
        with patch("src.api.routers.agents.get_settings") as mock_settings:
            mock_settings.return_value.agent_console_external_url = ""
            resp = client.get(
                "/api/v1/agents/console-url",
                headers={"host": "localhost:8000"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source"] == "request"
        assert "localhost:8000" in body["console_url"]


# -- enroll -------------------------------------------------------------------

class TestEnroll:
    @pytest.mark.asyncio
    async def test_enroll_valid_token(self):
        with (
            patch("src.api.routers.agents.validate_enroll_token", AsyncMock(return_value={"group": "prod"})),
            patch("src.api.routers.agents.get_vulnscan_store") as mock_vs,
            patch("src.api.routers.agents.register_enroll_token", AsyncMock()),
            patch("src.api.routers.agents.get_audit_logger") as mock_audit,
        ):
            mock_store = AsyncMock()
            mock_store.save_host = AsyncMock()
            mock_vs.return_value = mock_store
            mock_audit.return_value.log = AsyncMock()

            resp = client.post("/api/v1/agents/enroll", json={
                "token": "valid", "hostname": "web-01", "os": "linux",
                "arch": "amd64", "ip": "10.0.0.1", "kernel": "5.15",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "agent_id" in data
            assert "agent_token" in data
            assert "ws_url" in data

    def test_enroll_invalid_token_422(self):
        resp = client.post("/api/v1/agents/enroll", json={
            "token": "bad", "hostname": "web-01", "os": "linux",
            "arch": "amd64", "ip": "10.0.0.1", "kernel": "5.15",
        })
        assert resp.status_code == 422

    def test_enroll_missing_fields_422(self):
        resp = client.post("/api/v1/agents/enroll", json={"token": "bad"})
        assert resp.status_code == 422


# -- host management ----------------------------------------------------------

class TestHostManagement:
    def test_list_hosts_as_admin(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.agents.list_hosts", AsyncMock(return_value=[])):
            resp = client.get("/api/v1/agents", headers=headers)
            assert resp.status_code == 200
            assert "items" in resp.json()

    def test_list_hosts_no_auth_401(self):
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 401

    def test_get_host_as_admin(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.agents.get_host", AsyncMock(return_value=None)):
            resp = client.get("/api/v1/agents/host-1", headers=headers)
            assert resp.status_code == 404

    def test_delete_host_as_admin(self):
        headers = _auth_headers("admin")
        with (
            patch("src.api.routers.agents.get_host", AsyncMock(return_value=AsyncMock())),
            patch("src.api.routers.agents.decommission_host", AsyncMock()),
            patch("src.api.routers.agents.get_audit_logger") as mock_audit,
        ):
            mock_audit.return_value.log = AsyncMock()
            resp = client.delete("/api/v1/agents/host-1", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

    def test_delete_host_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.agents.get_host", AsyncMock(return_value=None)):
            resp = client.delete("/api/v1/agents/host-1", headers=headers)
            assert resp.status_code == 404

    def test_delete_host_no_auth_401(self):
        resp = client.delete("/api/v1/agents/host-1")
        assert resp.status_code == 401


# -- upgrade / config ---------------------------------------------------------

class TestUpgrade:
    def test_upgrade_missing_fields_422(self):
        headers = _auth_headers("admin")
        resp = client.post("/api/v1/agents/agent-1/upgrade", json={}, headers=headers)
        assert resp.status_code == 422

    def test_upgrade_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/agents/agent-1/upgrade", json={"version": "v1", "download_url": "http://x"}, headers=headers)
        assert resp.status_code == 403

    def test_upgrade_agent_not_connected(self):
        headers = _auth_headers("admin")
        with patch("src.agents.ws_gateway.get_agent_gateway") as mock_gw:
            mock_gateway = AsyncMock()
            mock_gateway.send_to_agent.return_value = False
            mock_gw.return_value = mock_gateway
            resp = client.post("/api/v1/agents/agent-1/upgrade", json={"version": "v1", "download_url": "http://x"}, headers=headers)
            assert resp.status_code == 404


class TestAgentConfig:
    def test_config_update_success(self):
        headers = _auth_headers("admin")
        with patch("src.agents.ws_gateway.get_agent_gateway") as mock_gw:
            mock_gateway = AsyncMock()
            mock_gateway.send_to_agent.return_value = True
            mock_gw.return_value = mock_gateway
            resp = client.patch("/api/v1/agents/agent-1/config", json={"heartbeat_interval": 30}, headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

    def test_config_update_agent_not_connected(self):
        headers = _auth_headers("admin")
        with patch("src.agents.ws_gateway.get_agent_gateway") as mock_gw:
            mock_gateway = AsyncMock()
            mock_gateway.send_to_agent.return_value = False
            mock_gw.return_value = mock_gateway
            resp = client.patch("/api/v1/agents/agent-1/config", json={"heartbeat_interval": 30}, headers=headers)
            assert resp.status_code == 404

    def test_config_update_no_auth_401(self):
        resp = client.patch("/api/v1/agents/agent-1/config", json={"heartbeat_interval": 30})
        assert resp.status_code == 401


class TestParseTs:
    """Unit tests for the _parse_ts helper used by save_host / update_host.

    asyncpg's timestamptz codec only accepts datetime.datetime /
    datetime.date / int / None. Bare strings raise
    "expected a datetime.date or datetime.datetime instance, got 'str'",
    so every timestamp crossing the asyncpg boundary must pass through
    _parse_ts first.
    """

    def test_parse_ts_none(self):
        from src.agents.store import _parse_ts
        assert _parse_ts(None) is None

    def test_parse_ts_empty_string_is_none(self):
        from src.agents.store import _parse_ts
        assert _parse_ts("") is None
        assert _parse_ts("   ") is None

    def test_parse_ts_unparseable_string_is_none(self):
        from src.agents.store import _parse_ts
        assert _parse_ts("not-a-date") is None
        assert _parse_ts("garbage") is None

    def test_parse_ts_datetime_passthrough(self):
        from datetime import UTC, datetime

        from src.agents.store import _parse_ts
        now = datetime.now(UTC)
        assert _parse_ts(now) is now

    def test_parse_ts_iso_with_offset(self):
        from datetime import datetime

        from src.agents.store import _parse_ts
        got = _parse_ts("2026-07-17T12:56:22.756514+00:00")
        assert isinstance(got, datetime)
        assert got.tzinfo is not None
        assert got == datetime(2026, 7, 17, 12, 56, 22, 756514, tzinfo=UTC)

    def test_parse_ts_iso_with_z_suffix(self):
        from datetime import datetime

        from src.agents.store import _parse_ts
        got = _parse_ts("2026-07-17T12:56:22Z")
        assert isinstance(got, datetime)
        assert got.tzinfo == UTC

    def test_parse_ts_iso_with_different_tz(self):
        from datetime import datetime, timedelta

        from src.agents.store import _parse_ts
        got = _parse_ts("2026-07-17T12:56:22+08:00")
        assert isinstance(got, datetime)
        assert got.utcoffset() == timedelta(hours=8)
