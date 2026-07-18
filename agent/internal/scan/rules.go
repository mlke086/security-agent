package scan

import (
	"encoding/json"
	"sync"
)

var (
	currentRules []RuleDef
	rulesMu      sync.RWMutex
)

// GetRules returns the current active rule set (thread-safe).
func GetRules() []RuleDef {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return currentRules
}

// LoadRules atomically replaces the active rule set from a JSON byte slice.
func LoadRules(data []byte) error {
	var pack struct {
		Version   string   `json:"version"`
		Rules     []RuleDef `json:"rules"`
		Signature string   `json:"signature"`
	}
	if err := json.Unmarshal(data, &pack); err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	currentRules = pack.Rules
	return nil
}
