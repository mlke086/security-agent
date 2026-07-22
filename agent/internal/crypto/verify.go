// Package crypto provides Ed25519 signature verification for incoming server commands.
package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
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

	// Guard against an unconfigured server public key. If PublicKey is empty
	// (server_public_key never delivered -- e.g. the install.sh pre-enroll
	// path writes config.json without it, and the agent skips enrollment
	// because AgentID is already set), ed25519.Verify panics with
	// "bad public key length: 0" in the read-loop goroutine -> unrecovered ->
	// process exit -> systemd Restart=always crash loop. HandleUpgrade /
	// HandleRuleUpdate already nil-check; Verify must too. P0-GO-01.
	if len(PublicKey) == 0 {
		return fmt.Errorf("server public key not configured; cannot verify %s", msgType)
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
	// P3-1 修复：canonical 签名串含敏感数据，仅 AGENT_DEBUG=1 时打印。
	if os.Getenv("AGENT_DEBUG") == "1" {
		log.Printf("[crypto] verify type=%q ts=%q canonical=%q", msgType, ts, canonicalJSON(payloadObj))
	}

	// Canonicalise: Python json.dumps(sort_keys=True) is the source of truth on
	// the signing side. Go json.Marshal on a map[string]interface{} does NOT
	// guarantee key order, so we walk the tree and emit sorted keys to match
	// the Python output byte-for-byte. P1-GO-4 (2026-07-19).
	canonicalPayload := canonicalJSON(payloadObj)
	canonical := fmt.Sprintf("%s|%s|%s", msgType, ts, canonicalPayload)

	if !ed25519.Verify(PublicKey, []byte(canonical), sig) {
		return fmt.Errorf("Ed25519 signature verification failed for %s", msgType)
	}
	return nil
}

// canonicalJSON returns a JSON encoding of v with object keys sorted
// lexicographically at every depth. This mirrors Python 3's
// json.dumps(sort_keys=True, ensure_ascii=False) which the server uses
// when signing -- without the same key ordering, the Ed25519 signature
// over the canonical string never matches. Numbers are marshalled via
// strconv so 1.0 vs 1 stay distinct (json.Marshal would coerce).
//
// We do the work with reflection-free type switches because every value
// here is JSON-originated and therefore fits one of the eight cases below.
func canonicalJSON(v interface{}) string {
	var b []byte
	b = appendCanonical(b, v)
	return string(b)
}

func appendCanonical(dst []byte, v interface{}) []byte {
	switch x := v.(type) {
	case map[string]interface{}:
		// Collect keys, sort, recurse.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
				dst = append(dst, ' ') // match Python json.dumps
			}
			// Match Python json.dumps default: keys are not escaped to \uXXXX.
			dst = strconv.AppendQuote(dst, k)
			dst = append(dst, ':')
			dst = append(dst, ' ') // match Python json.dumps ": " separator
			dst = appendCanonical(dst, x[k])
		}
		dst = append(dst, '}')
	case []interface{}:
		dst = append(dst, '[')
		for i, item := range x {
			if i > 0 {
				dst = append(dst, ',')
				// P1-GO-4: insert a space after each "," so [1, 2, 3]
				// not [1,2,3]. Python json.dumps default emits the
				// space; without it the canonical string diverges
				// byte-for-byte from the signer's and Verify fails.
				dst = append(dst, ' ')
			}
			dst = appendCanonical(dst, item)
		}
		dst = append(dst, ']')
	case string:
		dst = strconv.AppendQuote(dst, x)
	case bool:
		if x {
			dst = append(dst, "true"...)
		} else {
			dst = append(dst, "false"...)
		}
	case float64:
		// json.Unmarshal always produces float64 for numbers. Python
		// json.dumps keeps integers as integers; we mimic that by checking
		// whether the value is integral and has no precision loss, then
		// emitting as int. Otherwise fall through to json.Marshal which
		// keeps the float formatting.
		if x == float64(int64(x)) {
			dst = strconv.AppendInt(dst, int64(x), 10)
		} else {
			dst = strconv.AppendFloat(dst, x, 'g', -1, 64)
		}
	case nil:
		dst = append(dst, "null"...)
	default:
		// Fallback for types we did not anticipate (e.g. json.Number).
		jb, _ := json.Marshal(x)
		dst = append(dst, jb...)
	}
	return dst
}

// CanonicalJSONForTest exposes the canonical form for the test suite in
// other packages (comm/client_test.go). It is NOT part of the package's
// stable API -- keep the underscore name so any drift in the helper is
// obvious. The string is built with the same spacing rules as Verify's
// internal canonical payload, so a payload round-tripping through
// json.Marshal -> canonicalJSON -> json.Unmarshal produces the exact
// bytes Verify signs over.
func CanonicalJSONForTest(v interface{}) string {
	return canonicalJSON(v)
}
