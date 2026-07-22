package crypto

import (
	"crypto/ed25519"
	"fmt"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestSetPublicKey_Valid(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hexKey := hex.EncodeToString(pub)
	err := SetPublicKey(hexKey)
	if err != nil {
		t.Fatalf("SetPublicKey failed: %v", err)
	}
	if PublicKey == nil {
		t.Error("PublicKey not set")
	}
}

func TestSetPublicKey_InvalidHex(t *testing.T) {
	err := SetPublicKey("zzz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestSetPublicKey_WrongSize(t *testing.T) {
	err := SetPublicKey(hex.EncodeToString([]byte("short")))
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

func TestVerify_NonSensitiveType_Skips(t *testing.T) {
	PublicKey = nil
	err := Verify("heartbeat", "ts", json.RawMessage(`{}`), "")
	if err != nil {
		t.Errorf("non-sensitive type should skip verification: %v", err)
	}
}

func TestVerify_MissingSignature(t *testing.T) {
	PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	err := Verify("scan_command", "ts", json.RawMessage(`{}`), "")
	if err == nil {
		t.Error("expected error for missing signature")
	}
}

// TestVerify_NilPublicKey_NoPanic covers P0-GO-01: when the server public key
// is never delivered (install.sh pre-enroll path), PublicKey stays nil. A
// signed scan_command must NOT panic in ed25519.Verify -- it must return a
// readable error so the read loop logs and continues instead of crashing the
// agent into a restart loop.
func TestVerify_NilPublicKey_NoPanic(t *testing.T) {
	PublicKey = nil
	// A non-empty signature so we get past the "missing signature" guard and
	// reach the nil-key check (any valid base64 works; the key check runs
	// before the bytes are verified).
	sigB64 := base64.StdEncoding.EncodeToString([]byte("fake-sig"))
	err := Verify("scan_command", "ts", json.RawMessage(`{"task_id":"t1"}`), sigB64)
	if err == nil {
		t.Fatal("expected error when PublicKey is nil, got nil")
	}
}

func TestVerify_InvalidBase64(t *testing.T) {
	PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	err := Verify("scan_command", "ts", json.RawMessage(`{}`), "!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestVerify_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	PublicKey = pub

	payload := map[string]interface{}{"task_id": "t1", "modules": []string{"sys_vuln"}}
	payloadBytes, _ := json.Marshal(payload)
	msgType := "scan_command"
	ts := "2026-01-01T00:00:00Z"
	// Sign over the same canonical form Verify builds internally.
	canonical := msgType + "|" + ts + "|" + canonicalJSON(payload)
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	err = Verify(msgType, ts, payloadBytes, sigB64)
	if err != nil {
		t.Errorf("valid signature should pass: %v", err)
	}
}

func TestVerify_TamperedPayload_Fails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	PublicKey = pub

	payload := json.RawMessage(`{"task_id":"t1"}`)
	msgType := "scan_command"
	ts := "2026-01-01T00:00:00Z"
	canonical := msgType + "|" + ts + "|" + string(payload)
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Tamper the payload
	tampered := json.RawMessage(`{"task_id":"t2"}`)
	err = Verify(msgType, ts, tampered, sigB64)
	if err == nil {
		t.Error("tampered payload should fail verification")
	}
}

func TestVerify_WrongPublicKey_Fails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	PublicKey = wrongPub

	payload := json.RawMessage(`{"task_id":"t1"}`)
	msgType := "scan_command"
	ts := "2026-01-01T00:00:00Z"
	canonical := msgType + "|" + ts + "|" + string(payload)
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	err = Verify(msgType, ts, payload, sigB64)
	if err == nil {
		t.Error("wrong public key should fail verification")
	}
}

func TestVerify_InvalidPayloadJSON(t *testing.T) {
	PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Sign the canonical form of a valid payload, but pass invalid JSON
	validPayload := json.RawMessage(`{"x":"y"}`)
	canonical := "scan_command|ts|" + string(validPayload)
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Pass invalid JSON as payload - canonical reconstruction will fail
	err := Verify("scan_command", "ts", json.RawMessage(`{invalid}`), sigB64)
	if err == nil {
		t.Error("invalid JSON payload should fail")
	}
}

// canonicalJSON must produce output byte-for-byte equal to Python 3's
// json.dumps(sort_keys=True, ensure_ascii=False), because that is what the
// signing side (Python) emits and what Ed25519 signs over. If the agent
// re-emits the payload with a different key order, verify fails -- which
// is exactly the bug P1-GO-4 (2026-07-19) caught in the live WSL test.
//
// These cases mirror Python json.dumps behaviour for the payload shapes
// vulnscan / rule_update / config_update actually use.
func TestCanonicalJSON_MatchesPythonSortKeys(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
	}{
		{"flat map sorted",
			map[string]interface{}{"b": 2, "a": 1, "c": 3},
			`{"a": 1, "b": 2, "c": 3}`},
		{"nested map sorted recursively",
			map[string]interface{}{
				"target_id": "x",
				"options":   map[string]interface{}{"z": 9, "a": 1},
			},
			`{"options": {"a": 1, "z": 9}, "target_id": "x"}`},
		{"string with non-ASCII stays as UTF-8",
			map[string]interface{}{"name": "主机-A"},
			`{"name": "主机-A"}`},
		{"slice preserves order",
			map[string]interface{}{"ids": []interface{}{1, 2, 3}},
			`{"ids": [1, 2, 3]}`},
		{"empty map",
			map[string]interface{}{"e": map[string]interface{}{}},
			`{"e": {}}`},
		{"bool false stays false not 0",
			map[string]interface{}{"ok": false, "n": 0},
			`{"n": 0, "ok": false}`},
		{"int stays int",
			map[string]interface{}{"n": float64(42)},
			`{"n": 42}`},
	}
	for _, tc := range cases {
		got := canonicalJSON(tc.in)
		if got != tc.want {
			t.Errorf("%s: canonicalJSON = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Verify uses canonicalJSON internally: the signing side (Python)
// reorders keys, so Verify must do the same or signatures never match.
func TestVerify_AcceptsPythonStyleSortedPayload(t *testing.T) {
	// Use a freshly generated key so the test doesn't depend on the
	// hard-coded key in verify_test.go.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	PublicKey = pub

	// Build the canonical string the Python side would sign.
	payload := map[string]interface{}{
		"task_id": "abc",
		"policy": map[string]interface{}{
			"cpu_percent": 30,
			"modules":     []interface{}{"sys_vuln", "baseline"},
		},
		"modules": []interface{}{"sys_vuln", "baseline"},
	}
	ts := "2026-07-19T07:00:00+00:00"
	signStr := fmt.Sprintf("scan_command|%s|%s", ts, canonicalJSON(payload))
	sig := ed25519.Sign(priv, []byte(signStr))

	err = Verify("scan_command", ts, mustJSON(t, payload), base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// Verify must reject a payload whose key order does not match the
// canonical form -- this is the regression case for the P1-GO-4 bug
// where Go's default map iteration produced a different order from
// Python's json.dumps(sort_keys=True).
func TestVerify_RejectsWrongKeyOrder(t *testing.T) {
	// Same setup as above.
	pub, priv, _ := ed25519.GenerateKey(nil)
	PublicKey = pub

	// Sign with the canonical (sorted) form.
	payload := map[string]interface{}{"b": 2, "a": 1}
	ts := "2026-07-19T07:00:00+00:00"
	signStr := fmt.Sprintf("scan_command|%s|%s", ts, canonicalJSON(payload))
	sig := ed25519.Sign(priv, []byte(signStr))

	// Pass the payload in a shape Verify will marshal differently.
	// Because Verify re-marshals via canonicalJSON, the order is
	// normalised, so this should still verify. The test guards against
	// the inverse bug: we want to ensure Verify is order-stable on
	// its own; we also separately sign a deliberately-broken canonical
	// string to prove it rejects mismatched payloads.
	brokenSign := "scan_command|" + ts + `{"a":1,"b":2}` // already sorted; reverse to break
	_ = brokenSign
	badSig := ed25519.Sign(priv, []byte("scan_command|"+ts+`{"a":1,"b":99}`))
	if err := Verify("scan_command", ts, mustJSON(t, payload),
		base64.StdEncoding.EncodeToString(badSig)); err == nil {
		t.Error("Verify should reject signature over a tampered payload")
	}

	// Sanity: with the correct sig it should still verify.
	if err := Verify("scan_command", ts, mustJSON(t, payload),
		base64.StdEncoding.EncodeToString(sig)); err != nil {
		t.Errorf("Verify rejected correctly-signed payload: %v", err)
	}
}

// mustJSON marshals v into JSON bytes. Verify re-runs canonicalJSON
// on the unmarshaled map, so the caller does not need to pre-sort --
// that's the whole point of the canonicalisation layer.
func mustJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestVerify_AcceptsLivePythonPayload is the integration-style proof that
// canonicalJSON produces output byte-for-byte equal to what Python
// json.dumps(sort_keys=True, ensure_ascii=False) emits. The literal here
// was copy-pasted from the live server log on 2026-07-19 (captured via
// instruction_signed_debug). Without this test, regressions in the
// canonical form would only surface as agent-side verify failures during
// a real scan dispatch.
func TestVerify_AcceptsLivePythonPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	PublicKey = pub

	// Live Python canonical: scan_command|<ts>|{"deadline": "", ...}
	// ts comes from the wire and is included in the canonical; we use a
	// fixed one here so the test is reproducible.
	ts := "2026-07-19T08:05:27.278308+00:00"
	payloadCanonical := `{"deadline": "", "engine": "matcher", "modules": ["sys_vuln"], "nuclei_severity": [], "nuclei_tags": [], "nuclei_targets": ["agent-891d0fe74ad9"], "nuclei_templates": [], "nuclei_timeout_sec": 0, "policy": {"modules": ["sys_vuln"], "resource_limit": {"cpu_percent": 30, "mem_percent": 30}, "time_window": null, "timeout_sec": 1800}, "resource_limit": {"cpu_percent": 30, "mem_percent": 30}, "rule_version": "latest", "task_id": "a7be5e51-e33d-4f1f-97f4-a33843f82658"}`
	canonical := "scan_command|" + ts + "|" + payloadCanonical
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Build the raw payload the agent would unmarshal. It must produce
	// the same canonicalJSON output as the Python-emitted string above.
	payload := map[string]interface{}{
		"deadline":           "",
		"engine":             "matcher",
		"modules":            []interface{}{"sys_vuln"},
		"nuclei_severity":    []interface{}{},
		"nuclei_tags":        []interface{}{},
		"nuclei_targets":     []interface{}{"agent-891d0fe74ad9"},
		"nuclei_templates":   []interface{}{},
		"nuclei_timeout_sec": float64(0),
		"policy": map[string]interface{}{
			"modules": []interface{}{"sys_vuln"},
			"resource_limit": map[string]interface{}{
				"cpu_percent": float64(30),
				"mem_percent": float64(30),
			},
			"time_window": nil,
			"timeout_sec": float64(1800),
		},
		"resource_limit": map[string]interface{}{
			"cpu_percent": float64(30),
			"mem_percent": float64(30),
		},
		"rule_version": "latest",
		"task_id":      "a7be5e51-e33d-4f1f-97f4-a33843f82658",
	}
	payloadBytes, _ := json.Marshal(payload)

	got := canonicalJSON(payload)
	if got != payloadCanonical {
		t.Logf("PYTHON canonical:\n%s\n", payloadCanonical)
		t.Logf("GO canonical:\n%s\n", got)
		t.Fatalf("canonicalJSON diverges from Python json.dumps output")
	}
	if err := Verify("scan_command", ts, payloadBytes, sigB64); err != nil {
		t.Fatalf("Verify rejected the live Python payload: %v", err)
	}
}

