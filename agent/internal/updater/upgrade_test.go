package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
