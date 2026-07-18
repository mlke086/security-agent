package config

import (
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
