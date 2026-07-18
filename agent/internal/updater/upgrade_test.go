package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/security-agent/agent/internal/crypto"
)

// HandleUpgrade ends with os.Exit + renaming the running binary, so it is not
// unit-tested directly. HandleRuleUpdate (no exit) is tested here, and the
// Ed25519 verify logic is covered in package crypto.

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
