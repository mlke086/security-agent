// Package crypto provides Ed25519 signature verification for incoming server commands.
package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SensitiveTypes lists command types that MUST be signed.
var SensitiveTypes = map[string]bool{
	"scan_command":   true,
	"rule_update":    true,
	"agent_upgrade":  true,
	"scan_cancel":    true,
	"config_update":  true,
}

// PublicKey is the server's Ed25519 public key (hex-encoded).
// Set at startup from configuration or embedded at build time.
var PublicKey ed25519.PublicKey

// SetPublicKey configures the server public key for signature verification.
func SetPublicKey(hexKey string) error {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d, expected %d", len(key), ed25519.PublicKeySize)
	}
	PublicKey = ed25519.PublicKey(key)
	return nil
}

// Verify checks the Ed25519 signature on an incoming message.
// Returns nil if verification passes or the message type does not require signing.
// Returns an error if verification fails.
func Verify(msgType string, ts string, payload json.RawMessage, sigB64 string) error {
	if !SensitiveTypes[msgType] {
		return nil // Not a sensitive command, skip verification
	}
	if sigB64 == "" {
		return fmt.Errorf("missing signature for sensitive command %s", msgType)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Reconstruct canonical signing payload: type|ts|sorted_json(payload)
	var payloadObj map[string]interface{}
	if err := json.Unmarshal(payload, &payloadObj); err != nil {
		return fmt.Errorf("failed to parse payload: %w", err)
	}

	// Sort keys for canonical representation
	payloadBytes, _ := json.Marshal(payloadObj)
	// Re-marshal with sorted keys
	var normalized map[string]interface{}
	json.Unmarshal(payloadBytes, &normalized)
	payloadSorted, _ := json.Marshal(normalized)
	_ = sort.StringSlice{} // ensure sort is imported

	canonical := fmt.Sprintf("%s|%s|%s", msgType, ts, string(payloadSorted))

	if !ed25519.Verify(PublicKey, []byte(canonical), sig) {
		return fmt.Errorf("Ed25519 signature verification failed for %s", msgType)
	}
	return nil
}
