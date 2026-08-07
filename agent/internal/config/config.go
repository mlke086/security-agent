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
	// RuleVersion is the rule-pack version this agent last loaded. Heartbeat
	// reports it so the server knows whether to push a rule_update. Provisioned
	// by /enroll (enroll.py writes it into config.json) and updated in place
	// whenever HandleRuleUpdate hot-loads a new pack.
	RuleVersion     string `json:"rule_version"`
	HeartbeatSec    int    `json:"heartbeat_sec"`
	// MetricsIntervalSec 是 host_metrics 性能上报间隔（秒），独立于心跳
	// （需求①）。0/缺省由 metrics.Reporter 兜底为 15s；服务端可通过
	// config_update 下发热更新。
	MetricsIntervalSec int `json:"metrics_interval_sec"`
	// MetricsMounts 是磁盘采样的挂载点列表（可选；需求①）。空时取
	// 平台默认（"/" 或 Windows "C:"）。v1 仅用第一个挂载点。
	MetricsMounts []string `json:"metrics_mounts"`
	ResourceLimit   struct {
		CPUPercent int `json:"cpu_percent"`
		MemPercent int `json:"mem_percent"`
	} `json:"resource_limit"`

	// AgentVersion is the compiled-in agent version (from internal/version).
	// Set by main.go at startup; not persisted in config.json.
	AgentVersion string `json:"-"`
}

// DefaultConfigPath returns the OS-specific config file path.
//
// F-WSL (2026-07-21): respect SECAGENT_HOME so a non-root dev / WSL
// install can run without sudo. SECAGENT_HOME wins over the legacy
// OS-specific hardcoded paths.
func DefaultConfigPath() string {
	if h := os.Getenv("SECAGENT_HOME"); h != "" {
		return filepath.Join(h, "config.json")
	}
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		return p
	}
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
		// 需求①：默认 15s，与 metrics.Reporter 的兜底一致。
		MetricsIntervalSec: 15,
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 60
	}
	if cfg.MetricsIntervalSec <= 0 {
		cfg.MetricsIntervalSec = 15
	}
	return cfg, nil
}

// Save writes configuration back to the file (atomically: tmp + rename,
// so a crash mid-write can never corrupt config.json -- which holds the
// agent_token; V13 P2-16).
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}
