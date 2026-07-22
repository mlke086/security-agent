package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	cfg := &Config{AgentID: "a1", AgentToken: "tok", ConsoleURL: "https://x", HeartbeatSec: 30}
	cfg.ResourceLimit.CPUPercent = 20
	cfg.ResourceLimit.MemPercent = 40
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AgentID != "a1" || loaded.AgentToken != "tok" || loaded.ConsoleURL != "https://x" {
		t.Errorf("fields mismatch: %+v", loaded)
	}
	if loaded.HeartbeatSec != 30 || loaded.ResourceLimit.CPUPercent != 20 || loaded.ResourceLimit.MemPercent != 40 {
		t.Errorf("nested/default mismatch: %+v", loaded)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadDefaultHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	os.WriteFile(path, []byte(`{"agent_id":"a"}`), 0o600)
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.HeartbeatSec != 60 {
		t.Errorf("default HeartbeatSec = %d, want 60", loaded.HeartbeatSec)
	}
}


// TestF1ServerPublicKeyPersistsThroughRestart locks the F1 regression
// (2026-07-21): the agent main() flow used to call cfg.Save() BEFORE
// assigning cfg.ServerPublicKey from the enroll response, so the next
// start would reload config.json without the key and silently skip
// crypto.SetPublicKey -- every signed scan_command then failed
// verify.go. The fix in main.go now assigns the field first; this
// test guarantees the storage layer can carry the key through a
// Save/Load cycle so the fix stays alive.
func TestF1ServerPublicKeyPersistsThroughRestart(t *testing.T) {
    path := filepath.Join(t.TempDir(), "cfg.json")
    pub := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    // Simulate the post-F1 enroll block: every field populated, then Save.
    cfg := &Config{
        AgentID:         "agent-f1",
        AgentToken:      "tok-f1",
        ConsoleURL:      "https://console.example",
        ServerPublicKey: pub,
        HeartbeatSec:    60,
    }
    cfg.ResourceLimit.CPUPercent = 30
    cfg.ResourceLimit.MemPercent = 30
    if err := cfg.Save(path); err != nil {
        t.Fatalf("first save: %v", err)
    }

    // Simulate process restart: a brand-new Load from disk.
    reloaded, err := Load(path)
    if err != nil {
        t.Fatalf("load after restart: %v", err)
    }
    if reloaded.ServerPublicKey != pub {
        t.Fatalf("ServerPublicKey lost across restart: got %q, want %q", reloaded.ServerPublicKey, pub)
    }
    if reloaded.AgentID != "agent-f1" || reloaded.AgentToken != "tok-f1" {
        t.Errorf("other credentials also lost: %+v", reloaded)
    }

    // And the JSON on disk must literally contain the field, so we are
    // sure the omission is not hidden by a zero-value reflection trick.
    raw, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("readFile: %v", err)
    }
    if !bytes.Contains(raw, []byte("server_public_key")) {
        t.Errorf("config.json on disk does not carry server_public_key field: %s", raw)
    }
}
