package scan

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	currentRules []RuleDef
	rulesMu      sync.RWMutex
)

// DefaultRulesPath returns the OS-specific path for the persisted rule pack.
// Rules are hot-loaded into memory and mirrored to disk so a restart doesn't
// lose them (the agent binary ships no built-in rules -- without this file a
// freshly restarted agent scans with an empty rule set and produces 0 findings).
//
// F-WSL (2026-07-21): respect SECAGENT_HOME so the persist path follows
// the operator's chosen prefix instead of hardcoded /etc/secagent.
func DefaultRulesPath() string {
	if h := os.Getenv("SECAGENT_HOME"); h != "" {
		return filepath.Join(h, "rules.json")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "secagent", "rules.json")
	}
	return "/etc/secagent/rules.json"
}

// GetRules returns the current active rule set (thread-safe).
func GetRules() []RuleDef {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return currentRules
}

// LoadRules atomically replaces the active rule set from a JSON byte slice and
// persists it to disk so it survives a restart.
func LoadRules(data []byte) error {
	var pack struct {
		Version   string    `json:"version"`
		Rules     []RuleDef `json:"rules"`
		Signature string    `json:"signature"`
	}
	if err := json.Unmarshal(data, &pack); err != nil {
		return err
	}
	rulesMu.Lock()
	currentRules = pack.Rules
	rulesMu.Unlock()

	// Persist to disk (best-effort; a failure to write shouldn't block the
	// hot-load that just succeeded in memory).
	if err := persistRules(data); err != nil {
		log.Printf("[scan] WARN: rules loaded in memory but failed to persist: %v", err)
	}
	return nil
}

// persistRules writes the raw rule-pack bytes to the default path.
func persistRules(data []byte) error {
	path := DefaultRulesPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadPersistedRules loads the rule pack from disk at startup. Returns the
// version string (empty if no persisted pack / parse error). A missing file is
// normal on first run -- the server will push a rule_update shortly.
func LoadPersistedRules() (string, error) {
	path := DefaultRulesPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var pack struct {
		Version   string    `json:"version"`
		Rules     []RuleDef `json:"rules"`
		Signature string    `json:"signature"`
	}
	if err := json.Unmarshal(data, &pack); err != nil {
		return "", err
	}
	rulesMu.Lock()
	currentRules = pack.Rules
	rulesMu.Unlock()
	log.Printf("[scan] loaded %d persisted rules v%s", len(pack.Rules), pack.Version)
	return pack.Version, nil
}
