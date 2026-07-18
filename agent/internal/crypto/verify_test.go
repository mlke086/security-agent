package crypto

import (
	"crypto/ed25519"
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
	// Normalise with sorted keys (Go json.Marshal sorts map keys)
	var normalized map[string]interface{}
	json.Unmarshal(payloadBytes, &normalized)
	payloadSorted, _ := json.Marshal(normalized)

	msgType := "scan_command"
	ts := "2026-01-01T00:00:00Z"
	canonical := msgType + "|" + ts + "|" + string(payloadSorted)
	sig := ed25519.Sign(priv, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	err = Verify(msgType, ts, payloadSorted, sigB64)
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
