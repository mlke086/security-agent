package comm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/queue"
)
// signTestMessage creates a real Ed25519 signature over the canonical
// "<type>|<ts>|<payload>" envelope used by crypto.Verify. Tests that exercise
// sensitive command dispatch must set crypto.PublicKey via a TestMain (or
// per-test helper) AND provide a real signature, otherwise crypto.Verify will
// rightly reject the message.
func signTestMessage(t *testing.T, msgType, ts string, payload []byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	crypto.PublicKey = pub
	canonical := string(msgType) + "|" + ts + "|" + string(payload)
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.StdEncoding.EncodeToString(sig)
}

func signedTestMsg(t *testing.T, msgType string, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, _ := json.Marshal(payload)
	ts := "2026-01-01T00:00:00Z"
	sig := signTestMessage(t, msgType, ts, payloadBytes)
	out := map[string]interface{}{
		"v":       1,
		"type":    msgType,
		"ts":      ts,
		"sig":     sig,
		"payload": json.RawMessage(payloadBytes),
	}
	b, _ := json.Marshal(out)
	return b
}


func TestNewClient(t *testing.T) {
	cfg := &config.Config{
		AgentID:    "agent-1",
		AgentToken: "token-1",
		ConsoleURL: "https://console:8000",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client.cfg != cfg {
		t.Error("client config mismatch")
	}
	if client.done == nil {
		t.Error("client done channel is nil")
	}
}

func TestHandleMessage_ScanCommand_RejectsBadSig(t *testing.T) {
	crypto.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	client, _ := NewClient(&config.Config{})
	received := false
	client.OnScanCommand = func(payload json.RawMessage) {
		received = true
	}

	raw := []byte(`{"v":1,"type":"scan_command","ts":"2026-01-01T00:00:00Z","sig":"AAAA","payload":{"task_id":"t1"}}`)
	client.handleMessage(raw)

	if received {
		t.Error("OnScanCommand should NOT be called with bad signature")
	}
}

func TestHandleMessage_RuleUpdate(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	received := false
	client.OnRuleUpdate = func(payload json.RawMessage) {
		received = true
	}

	raw := signedTestMsg(t, "rule_update", map[string]interface{}{"rule_version": "v2"})
	client.handleMessage(raw)

	if !received {
		t.Error("OnRuleUpdate was not called")
	}
}

func TestHandleMessage_AgentUpgrade(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	received := false
	client.OnAgentUpgrade = func(payload json.RawMessage) {
		received = true
	}

	raw := signedTestMsg(t, "agent_upgrade", map[string]interface{}{"version": "0.2.0"})
	client.handleMessage(raw)

	if !received {
		t.Error("OnAgentUpgrade was not called")
	}
}

func TestHandleMessage_ConfigUpdate(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	received := false
	client.OnConfigUpdate = func(payload json.RawMessage) {
		received = true
	}

	raw := signedTestMsg(t, "config_update", map[string]interface{}{"heartbeat_interval": 30})
	client.handleMessage(raw)

	if !received {
		t.Error("OnConfigUpdate was not called")
	}
}

func TestHandleMessage_ScanCancel(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	raw := signedTestMsg(t, "scan_cancel", map[string]interface{}{})
	client.handleMessage(raw)
}

func TestHandleMessage_UnknownType(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	raw := []byte(`{"v":1,"type":"weird_type","ts":"","sig":"","payload":{}}`)
	client.handleMessage(raw)
}

func TestHandleMessage_InvalidJSON(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	client.handleMessage([]byte("not json"))
}

func TestSendStep_DisconnectedQueues(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	dbPath := t.TempDir() + "/test.db"
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	defer q.Close()
	client.Queue = q

	client.SendStep("task-1", "collect", "running", "step 1")

	count, err := q.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestSendResult_DisconnectedQueues(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	dbPath := t.TempDir() + "/test.db"
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	defer q.Close()
	client.Queue = q

	client.SendResult("task-1", "host-1", []map[string]string{}, 1, true)

	count, err := q.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestSendTaskAck_DisconnectedQueues(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	dbPath := t.TempDir() + "/test.db"
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	defer q.Close()
	client.Queue = q

	client.SendTaskAck("task-1", true, "")

	count, err := q.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestSendUpdateAck_DisconnectedQueues(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	dbPath := t.TempDir() + "/test.db"
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	defer q.Close()
	client.Queue = q

	client.SendUpdateAck("rule_update", "v2", true, "")

	count, err := q.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 queued message, got %d", count)
	}
}

func TestProcessQueue_ReplaysMessages(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	dbPath := t.TempDir() + "/test.db"
	q, err := queue.Open(dbPath)
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	defer q.Close()
	client.Queue = q

	msg := map[string]interface{}{
		"v":   1,
		"type": "scan_step",
		"ts":  "2026-01-01T00:00:00Z",
		"payload": map[string]string{
			"task_id": "task-1",
			"step":    "collect",
			"status":  "done",
			"message": "ok",
		},
	}
	if err := q.Push("outgoing", msg); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := q.Push("outgoing", msg); err != nil {
		t.Fatalf("Push: %v", err)
	}

	client.processQueue()

	count, err := q.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 re-queued messages, got %d", count)
	}
}

func TestProcessQueue_EmptyQueue(t *testing.T) {
	client, _ := NewClient(&config.Config{})
	client.processQueue()
}
