package updater

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/security-agent/agent/internal/crypto"
)

// Upgrade replacement is tested against a temporary executable path. The real
// process restart is owned by cmd/agent after the success ack has been sent.

func TestHandleRuleUpdateSuccess(t *testing.T) {
	// P1-GO-2: HandleRuleUpdate now verifies Ed25519 signature on the pack
	// bytes. Generate a keypair, sign the pack, expose the public key via
	// crypto.PublicKey, and ensure the request carries the signature.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crypto.PublicKey = pub

	pack := []byte(`{"version":"2026.07.14","rules":[{"id":"CVE-X","category":"sys_vuln","cve":"CVE-X","name":"x","severity":"high","check":{"type":"package_version","name":"pkg","op":"lt","value":"9.0"},"fix":"upgrade"}]}`)
	sig := ed25519.Sign(priv, pack)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pack)
	}))
	defer srv.Close()

	var ackKind, ackVer string
	var ackOk bool
	ack := func(kind, version string, ok bool, _ string) { ackKind, ackVer, ackOk = kind, version, ok }

	if err := HandleRuleUpdate(RuleUpdateRequest{RuleVersion: "2026.07.14", DownloadURL: srv.URL, Signature: sigB64}, ack); err != nil {
		t.Fatalf("HandleRuleUpdate: %v", err)
	}
	if !ackOk || ackKind != "rule" || ackVer != "2026.07.14" {
		t.Errorf("ack wrong: kind=%s ver=%s ok=%v", ackKind, ackVer, ackOk)
	}
}

func TestHandleRuleUpdateDownloadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ackOk := true
	ack := func(_, _ string, ok bool, _ string) { ackOk = ok }

	if err := HandleRuleUpdate(RuleUpdateRequest{RuleVersion: "v", DownloadURL: srv.URL}, ack); err == nil {
		t.Error("expected error on HTTP 500")
	}
	if ackOk {
		t.Error("expected ack ok=false")
	}
}

func TestHandleUpgradeReplacesExecutableAndKeepsBackup(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crypto.PublicKey = pub

	newBinary := []byte("new-agent-binary")
	hash := sha256.Sum256(newBinary)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, hash[:]))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
			t.Errorf("Authorization=%q", got)
		}
		if got := r.URL.Query().Get("agent_id"); got != "agent-1" {
			t.Errorf("agent_id=%q", got)
		}
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()

	dir := t.TempDir()
	executable := filepath.Join(dir, "agent")
	if err := os.WriteFile(executable, []byte("old-agent-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	err = HandleUpgrade(UpgradeRequest{
		Version:        "0.2.0",
		DownloadURL:    srv.URL,
		Signature:      signature,
		AgentID:        "agent-1",
		AgentToken:     "agent-token",
		ExecutablePath: executable,
	})
	if err != nil {
		t.Fatalf("HandleUpgrade: %v", err)
	}

	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBinary) {
		t.Fatalf("new executable=%q", got)
	}
	backup, err := os.ReadFile(executable + ".old")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "old-agent-binary" {
		t.Fatalf("backup=%q", backup)
	}
}

func TestHandleUpgradeBadSignatureLeavesExecutableUntouched(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crypto.PublicKey = pub

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("untrusted"))
	}))
	defer srv.Close()

	executable := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(executable, []byte("trusted"), 0o755); err != nil {
		t.Fatal(err)
	}
	err = HandleUpgrade(UpgradeRequest{
		Version:        "0.2.0",
		DownloadURL:    srv.URL,
		Signature:      base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		ExecutablePath: executable,
	})
	if err == nil {
		t.Fatal("expected signature verification error")
	}
	got, _ := os.ReadFile(executable)
	if string(got) != "trusted" {
		t.Fatalf("executable changed after rejected upgrade: %q", got)
	}
}

// buildNucleiZip builds an in-memory zip whose root entry “name“ carries
// “content“ plus a decoy README so we can assert the extractor picks the
// right entry by base name.
func buildNucleiZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for _, e := range []struct {
		n string
		c []byte
	}{
		{"README.md", []byte("ignore me")},
		{name, content},
	} {
		w, err := zw.Create(e.n)
		if err != nil {
			t.Fatalf("zip create %s: %v", e.n, err)
		}
		if _, err := w.Write(e.c); err != nil {
			t.Fatalf("zip write %s: %v", e.n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestHandleNucleiUpgradeSwapsBinary(t *testing.T) {
	// SECAGENT_HOME makes nuclei.NewCLIRunner().BinaryPath resolve under a
	// temp dir so the test never touches /opt/secagent.
	home := t.TempDir()
	t.Setenv("SECAGENT_HOME", home)

	newBin := []byte("nuclei-v3.11.0-binary")
	zipBytes := buildNucleiZip(t, "nuclei", newBin)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	var ackKind, ackVer string
	var ackOk bool
	ack := func(kind, version string, ok bool, _ string) { ackKind, ackVer, ackOk = kind, version, ok }

	if err := HandleNucleiUpgrade(NucleiUpgradeRequest{Version: "3.11.0", DownloadURL: srv.URL}, ack); err != nil {
		t.Fatalf("HandleNucleiUpgrade: %v", err)
	}
	if !ackOk || ackKind != "nuclei" || ackVer != "3.11.0" {
		t.Errorf("ack wrong: kind=%s ver=%s ok=%v", ackKind, ackVer, ackOk)
	}

	got, err := os.ReadFile(filepath.Join(home, "bin", "nuclei"))
	if err != nil {
		t.Fatalf("read installed nuclei: %v", err)
	}
	if string(got) != string(newBin) {
		t.Fatalf("installed binary = %q, want %q", got, newBin)
	}
}

func TestHandleNucleiUpgradeMissingEntryFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SECAGENT_HOME", home)

	// zip has only a README, no nuclei binary -> extraction must fail and the
	// (non-existent) target must remain absent.
	zipBytes := buildNucleiZip(t, "README.md", []byte("no binary here"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	ackOk := true
	ack := func(_, _ string, ok bool, _ string) { ackOk = ok }

	if err := HandleNucleiUpgrade(NucleiUpgradeRequest{Version: "3.11.0", DownloadURL: srv.URL}, ack); err == nil {
		t.Fatal("expected error when zip lacks the nuclei binary")
	}
	if ackOk {
		t.Error("expected ack ok=false")
	}
	if _, err := os.Stat(filepath.Join(home, "bin", "nuclei")); !os.IsNotExist(err) {
		t.Errorf("expected no nuclei file, got err=%v", err)
	}
}

// buildTemplatesZip builds an in-memory zip that mimics the projectdiscovery
// release layout: a top-level wrapper dir (nuclei-templates-<ver>/) containing
// category subdirs with template files, plus a decoy root README.
func buildTemplatesZip(t *testing.T, wrapper string, files map[string]string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for name, content := range files {
		w, err := zw.Create(wrapper + "/" + name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestSharedTopLevelPrefix(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  string
	}{
		{"wrapper", []string{"nuclei-templates-10.4.6/cves/a.yaml", "nuclei-templates-10.4.6/exposures/b.yaml"}, "nuclei-templates-10.4.6/"},
		{"no_wrapper", []string{"cves/a.yaml", "exposures/b.yaml"}, ""},
		{"mixed", []string{"wrap/cves/a.yaml", "other/b.yaml"}, ""},
		{"root_file_breaks_wrapper", []string{"wrap/a.yaml", "root.yaml"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			zw := zip.NewWriter(buf)
			for _, n := range c.names {
				w, _ := zw.Create(n)
				_, _ = w.Write([]byte("x"))
			}
			_ = zw.Close()
			zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if got := sharedTopLevelPrefix(zr.File); got != c.want {
				t.Errorf("sharedTopLevelPrefix = %q, want %q", got, c.want)
			}
		})
	}
}

func TestHandleNucleiTemplatesUpdateStripsWrapperAndSwaps(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SECAGENT_HOME", home)

	// Pre-existing old template + a stale .new dir to confirm cleanup.
	tplDir := filepath.Join(home, "templates")
	_ = os.MkdirAll(tplDir, 0o755)
	_ = os.WriteFile(filepath.Join(tplDir, "old.yaml"), []byte("old"), 0o644)
	_ = os.MkdirAll(tplDir+".new", 0o755)

	zipBytes := buildTemplatesZip(t, "nuclei-templates-10.4.6", map[string]string{
		"cves/CVE-2024-1.yaml": "cve-template",
		"exposures/exp-1.yaml": "exposure-template",
		"README.md":            "ignore me",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	var ackKind, ackVer string
	var ackOk bool
	ack := func(kind, version string, ok bool, _ string) { ackKind, ackVer, ackOk = kind, version, ok }

	if err := HandleNucleiTemplatesUpdate(NucleiTemplatesUpdateRequest{Version: "10.4.6", DownloadURL: srv.URL}, ack); err != nil {
		t.Fatalf("HandleNucleiTemplatesUpdate: %v", err)
	}
	if !ackOk || ackKind != "nuclei_templates" || ackVer != "10.4.6" {
		t.Errorf("ack wrong: kind=%s ver=%s ok=%v", ackKind, ackVer, ackOk)
	}

	// Wrapper dir stripped: categories land directly under templates/.
	cve, err := os.ReadFile(filepath.Join(tplDir, "cves", "CVE-2024-1.yaml"))
	if err != nil {
		t.Fatalf("read installed cve template: %v", err)
	}
	if string(cve) != "cve-template" {
		t.Fatalf("cve template = %q", cve)
	}
	exp, _ := os.ReadFile(filepath.Join(tplDir, "exposures", "exp-1.yaml"))
	if string(exp) != "exposure-template" {
		t.Fatalf("exposure template = %q", exp)
	}

	// Old bundle moved to .old; stale .new cleaned up (no leftover staged dir).
	if _, err := os.Stat(filepath.Join(tplDir, "old.yaml")); !os.IsNotExist(err) {
		t.Errorf("old template should have been swapped out, got err=%v", err)
	}
	if _, err := os.Stat(tplDir + ".old"); err != nil {
		t.Errorf("expected .old backup, got err=%v", err)
	}
	if _, err := os.Stat(tplDir + ".new"); !os.IsNotExist(err) {
		t.Errorf("staged .new dir should be gone after swap, got err=%v", err)
	}
}

// G-P1-1 (V12): the three download paths must reject oversized bodies with
// a hard error + failure ack instead of OOMing / filling disk.

func TestHandleNucleiUpgradeRejectsOversizedZip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SECAGENT_HOME", home)

	// >200MB is rejected before any extraction happens.
	big := make([]byte, maxNucleiDownloadBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	ackFail := false
	ack := func(_ string, _ string, ok bool, _ string) { ackFail = !ok }

	err := HandleNucleiUpgrade(NucleiUpgradeRequest{Version: "3.11.0", DownloadURL: srv.URL}, ack)
	if err == nil {
		t.Fatal("expected error for oversized nuclei zip")
	}
	if !ackFail {
		t.Error("expected a failure ack for oversized nuclei zip")
	}
}

func TestHandleNucleiTemplatesUpdateRejectsOversized(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SECAGENT_HOME", home)

	big := make([]byte, maxTemplatesDownloadBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	ackFail := false
	ack := func(_ string, _ string, ok bool, _ string) { ackFail = !ok }

	err := HandleNucleiTemplatesUpdate(NucleiTemplatesUpdateRequest{Version: "10.4.6", DownloadURL: srv.URL}, ack)
	if err == nil {
		t.Fatal("expected error for oversized templates zip")
	}
	if !ackFail {
		t.Error("expected a failure ack for oversized templates zip")
	}
}

func TestHandleRuleUpdateRejectsOversizedPack(t *testing.T) {
	// Rule packs are small (<5MB); anything over the 100MB cap is a
	// misconfigured or malicious mirror.
	big := make([]byte, maxRuleDownloadBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	ackFail := false
	ack := func(_ string, _ string, ok bool, _ string) { ackFail = !ok }

	err := HandleRuleUpdate(RuleUpdateRequest{RuleVersion: "v", DownloadURL: srv.URL}, ack)
	if err == nil {
		t.Fatal("expected error for oversized rule pack")
	}
	if !ackFail {
		t.Error("expected a failure ack for oversized rule pack")
	}
}

func TestHandleUpgradeRejectsOversizedBinary(t *testing.T) {
	// The agent self-upgrade path must also refuse a body over the cap
	// instead of letting io.Copy fill the disk.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crypto.PublicKey = pub

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxNucleiDownloadBytes+1))
	}))
	defer srv.Close()

	dir := t.TempDir()
	executable := filepath.Join(dir, "agent")
	if err := os.WriteFile(executable, []byte("old-agent-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	err = HandleUpgrade(UpgradeRequest{
		Version:        "v",
		DownloadURL:    srv.URL,
		Signature:      "x",
		ExecutablePath: executable,
	})
	// The size check must fire during the download, BEFORE the signature
	// verification (which would reject "x").
	if err == nil {
		t.Fatal("expected error for oversized agent binary")
	}
	if want := "exceeds"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

// G-P1-2 (V12 阶段 5.1): a configured-but-unreadable CA must hard-fail the
// download instead of silently falling back to the system root CA.

func TestHTTPClientCAFailHard(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-ca.pem")
	client, err := httpClient(missing)
	if err == nil {
		t.Fatal("expected error for unreadable CA path")
	}
	if client != nil {
		t.Fatal("expected nil client on CA failure")
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Fatalf("error = %q, want read CA cert message", err)
	}
}

func TestHTTPClientCAInvalidPEM(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := httpClient(bad)
	if err == nil {
		t.Fatal("expected error for invalid PEM CA")
	}
	if client != nil {
		t.Fatal("expected nil client on invalid PEM")
	}
	if !strings.Contains(err.Error(), "invalid PEM") {
		t.Fatalf("error = %q, want invalid PEM message", err)
	}
}

func TestHTTPClientCAEmptyPathOK(t *testing.T) {
	client, err := httpClient("")
	if err != nil {
		t.Fatalf("empty CA path must not error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a client for empty CA path (system roots)")
	}
}
