package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds all agent configuration.
type Config struct {
	AgentID         string `json:"agent_id"`
	AgentToken      string `json:"agent_token"`
	ConsoleURL      string `json:"console_url"`
	CAPath          string `json:"ca_path"`
	EnrollToken     string `json:"enroll_token"`
	// ServerPublicKey is the hex-encoded Ed25519 public key the agent must
	// verify sensitive commands against. P0-GO-1. It can be provisioned
	// either by the /enroll response or via config.json.
	ServerPublicKey string `json:"server_public_key"`
	HeartbeatSec    int    `json:"heartbeat_sec"`
	ResourceLimit   struct {
		CPUPercent int `json:"cpu_percent"`
		MemPercent int `json:"mem_percent"`
	} `json:"resource_limit"`
}

// DefaultConfigPath returns the OS-specific config file path.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "secagent", "config", "config.json")
	}
	return "/etc/secagent/config.json"
}

// Load reads configuration from the config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{
		HeartbeatSec: 60,
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 60
	}
	return cfg, nil
}

// Save writes configuration back to the file.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
