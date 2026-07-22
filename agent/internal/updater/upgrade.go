// Package updater handles agent self-upgrade with gray-release support
// and rule pack hot-loading.
package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/scan"
)

// UpgradeRequest is the payload from server's agent_upgrade command.
type UpgradeRequest struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	Signature   string `json:"signature"`
}

// HandleUpgrade downloads, verifies, and applies a new agent binary.
func HandleUpgrade(req UpgradeRequest) error {
	log.Printf("[updater] downloading agent v%s from %s", req.Version, req.DownloadURL)

	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("secagent-%s-%s", req.Version, runtime.GOARCH))
	if runtime.GOOS == "windows" {
		tmpFile += ".exe"
	}

	resp, err := http.Get(req.DownloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("download write: %w", err)
	}
	f.Close()

	hash := hasher.Sum(nil)
	if req.Signature == "" {
		os.Remove(tmpFile)
		return fmt.Errorf("missing signature - agent_upgrade requires Ed25519 signature")
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if crypto.PublicKey == nil {
		os.Remove(tmpFile)
		return fmt.Errorf("server public key not configured - cannot verify upgrade")
	}
	if !ed25519.Verify(crypto.PublicKey, hash, sig) {
		os.Remove(tmpFile)
		return fmt.Errorf("Ed25519 signature verification failed - upgrade rejected")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpFile, 0o755); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}

	execPath, err := os.Executable()
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("find executable: %w", err)
	}

	oldPath := execPath + ".old"
	if runtime.GOOS == "windows" {
		os.Remove(oldPath)
	}
	os.Rename(execPath, oldPath)
	os.Rename(tmpFile, execPath)

	log.Printf("[updater] upgrade to v%s complete, restarting...", req.Version)
	os.Remove(oldPath)
	os.Exit(0)
	return nil
}

// RuleUpdateRequest is the payload from server's rule_update command.
type RuleUpdateRequest struct {
	RuleVersion string `json:"rule_version"`
	DownloadURL string `json:"download_url"`
	Signature   string `json:"signature"`
	// AgentID / AgentToken / CAPath are NOT part of the server payload; the
	// caller (main.go) fills them in so the pack download can authenticate
	// against /rules/pack/{version} (which requires a JWT or agent_token) and
	// trust the server's TLS cert when a self-signed CA is in use.
	// Left empty in unit tests (test server doesn't enforce auth / TLS).
	AgentID     string `json:"-"`
	AgentToken  string `json:"-"`
	CAPath      string `json:"-"`
}

// httpClient builds an *http.Client that trusts the configured CA (so
// self-signed console certs work) and has a 60s timeout (so a hung server
// can't block the rule-update goroutine forever). Mirrors the CA loading in
// comm/client.go Connect.
func httpClient(caPath string) *http.Client {
	client := &http.Client{Timeout: 60 * time.Second}
	if caPath == "" {
		return client
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		log.Printf("[updater] WARN: read CA failed (%v), using system roots", err)
		return client
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Printf("[updater] WARN: CA pool append failed, using system roots")
		return client
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}
	return client
}

// HandleRuleUpdate downloads and hot-loads new vulnerability rules (no restart).
//
// P1-GO-2: verify the Ed25519 signature on the response body before loading the
// rules. Without this a MitM (default ws:// channel is plain!) could swap rule
// packs to hide real findings or trigger SSRF against the agent.
func HandleRuleUpdate(req RuleUpdateRequest, sendAck func(kind, version string, ok bool, err string)) error {
	log.Printf("[updater] downloading rule pack v%s", req.RuleVersion)

	if req.Signature == "" {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, "missing signature") }
		return fmt.Errorf("missing signature - rule_update requires Ed25519 signature")
	}
	if crypto.PublicKey == nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, "server public key not configured") }
		return fmt.Errorf("server public key not configured - cannot verify rule update")
	}

	// 修复(P1-1/P1-2)：用带 CA + 超时的 http.Client，凭证走 Authorization
	// header（与 WS 链路一致，不把 token 拼进 URL 落日志/抓包）。agent_id 走
	// query（非敏感，后端用它 + header token 做 validate_agent_token）。
	downloadURL := req.DownloadURL
	httpReq, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, err.Error()) }
		return fmt.Errorf("build download request: %w", err)
	}
	if req.AgentID != "" {
		q := httpReq.URL.Query()
		q.Set("agent_id", req.AgentID)
		httpReq.URL.RawQuery = q.Encode()
	}
	if req.AgentID != "" && req.AgentToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.AgentToken)
	}
	resp, err := httpClient(req.CAPath).Do(httpReq)
	if err != nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, err.Error()) }
		return fmt.Errorf("download rule pack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, fmt.Sprintf("HTTP %d", resp.StatusCode)) }
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, err.Error()) }
		return fmt.Errorf("read rule pack: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, "invalid signature encoding") }
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(crypto.PublicKey, data, sig) {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, "Ed25519 verification failed") }
		return fmt.Errorf("Ed25519 signature verification failed - rule pack rejected")
	}

	if err := scan.LoadRules(data); err != nil {
		if sendAck != nil { sendAck("rule", req.RuleVersion, false, err.Error()) }
		return fmt.Errorf("load rules: %w", err)
	}

	log.Printf("[updater] rules v%s loaded", req.RuleVersion)
	// F-WSL (2026-07-21): the caller (main.go) records the new version
	// on the client so the next heartbeat reports it back.
	if sendAck != nil { sendAck("rule", req.RuleVersion, true, "") }
	return nil
}
