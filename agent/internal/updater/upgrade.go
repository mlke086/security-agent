// Package updater handles agent self-upgrade with gray-release support
// and rule pack hot-loading.
package updater

import (
	"archive/zip"
	"bytes"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/scan"
	"github.com/security-agent/agent/internal/scan/nuclei"
)

// Download size caps (G-P1-1 / V12): a malicious or misconfigured mirror
// must not be able to OOM the agent by streaming an unbounded body. The
// caps leave 2.5-5x headroom over realistic payloads (nuclei binary ~30MB,
// templates zip 50-200MB, rule pack <5MB).
const (
	maxNucleiDownloadBytes    = 200 * 1024 * 1024 // 200MB nuclei binary
	maxTemplatesDownloadBytes = 500 * 1024 * 1024 // 500MB templates zip
	maxRuleDownloadBytes      = 100 * 1024 * 1024 // 100MB rule pack
)

// readLimitedBody reads at most maxBytes from r and fails loudly when the
// stream exceeds the cap (instead of io.ReadAll's unbounded slurp).
func readLimitedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("download body exceeds %d bytes limit", maxBytes)
	}
	return data, nil
}

// ackFail sends a failure ack (when the callback is wired) and returns err
// (S-P2-17). The updater handlers used to repeat the sendAck+return pair ~24
// times; collapsing it here means a failure path can never forget the ack.
func ackFail(sendAck func(kind, version string, ok bool, err string), kind, version, ackMsg string, err error) error {
	if sendAck != nil {
		sendAck(kind, version, false, ackMsg)
	}
	return err
}

// UpgradeRequest is the payload from server's agent_upgrade command.
type UpgradeRequest struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	Signature   string `json:"signature"`
	// AgentID / AgentToken / CAPath are filled by main.go (json:"-")
	AgentID        string `json:"-"`
	AgentToken     string `json:"-"`
	CAPath         string `json:"-"`
	ExecutablePath string `json:"-"` // tests/helpers; empty uses os.Executable
}

// HandleUpgrade downloads, verifies, and applies a new agent binary.
func HandleUpgrade(req UpgradeRequest) error {
	log.Printf("[updater] downloading agent v%s from %s", req.Version, req.DownloadURL)

	if req.Signature == "" {
		return fmt.Errorf("missing signature - agent_upgrade requires Ed25519 signature")
	}
	if crypto.PublicKey == nil {
		return fmt.Errorf("server public key not configured - cannot verify upgrade")
	}

	execPath := req.ExecutablePath
	if execPath == "" {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("find executable: %w", err)
		}
		if runtime.GOOS == "windows" {
			return fmt.Errorf("in-process upgrade is not supported on Windows; use the service helper")
		}
	}

	httpReq, err := http.NewRequest(http.MethodGet, req.DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	if req.AgentID != "" {
		q := httpReq.URL.Query()
		q.Set("agent_id", req.AgentID)
		httpReq.URL.RawQuery = q.Encode()
	}
	if req.AgentToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.AgentToken)
	}
	client, err := httpClient(req.CAPath)
	if err != nil {
		return fmt.Errorf("build http client: %w", err)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	f, err := os.CreateTemp(filepath.Dir(execPath), ".secagent-upgrade-*")
	if err != nil {
		return fmt.Errorf("create staged binary: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile)

	hasher := sha256.New()
	// G-P1-1 (V12): cap the agent binary download too -- io.Copy streams
	// to disk so this is a disk-exhaustion guard rather than an OOM guard,
	// but an unbounded mirror could still fill the filesystem.
	limited := io.LimitReader(resp.Body, maxNucleiDownloadBytes+1)
	n, err := io.Copy(io.MultiWriter(f, hasher), limited)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("download write: %w", err)
	}
	if n > maxNucleiDownloadBytes {
		_ = f.Close()
		return fmt.Errorf("agent binary exceeds %d bytes limit", maxNucleiDownloadBytes)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(crypto.PublicKey, hasher.Sum(nil), sig) {
		return fmt.Errorf("Ed25519 signature verification failed - upgrade rejected")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpFile, 0o755); err != nil {
			return fmt.Errorf("chmod staged binary: %w", err)
		}
	}

	// P2-UPGRADE-02 (2026-07-22): only apply the staged binary once we
	// have validated everything. Returning an error here is recoverable:
	// the old binary is untouched and the caller acks the server with
	// "failed" instead of phantom-success.
	oldPath := execPath + ".old"
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous backup: %w", err)
	}
	if err := os.Rename(execPath, oldPath); err != nil {
		return fmt.Errorf("backup current executable: %w", err)
	}
	if err := os.Rename(tmpFile, execPath); err != nil {
		rollbackErr := os.Rename(oldPath, execPath)
		if rollbackErr != nil {
			return fmt.Errorf("install new executable: %w (rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("install new executable: %w", err)
	}

	// F3-SELINUX (2026-07-23): os.CreateTemp creates files with tmp_t selinux
	// context; os.Rename preserves it.  Without restorecon systemd refuses to
	// execve() the binary (203/EXEC). Best-effort: selinux may be disabled.
	if runtime.GOOS == "linux" {
		if err := exec.Command("restorecon", execPath).Run(); err != nil {
			log.Printf("[updater] WARN: restorecon %s failed: %v (selinux may be disabled)", execPath, err)
		}
	}

	log.Printf("[updater] upgrade to v%s staged; backup kept at %s", req.Version, oldPath)
	return nil
}

// ApplyStagedAndRestart asks the service manager to swap in the new binary.
// It must NOT block the ack path: the caller acks the server first and then
// invokes this in a background goroutine.
func ApplyStagedAndRestart(_ UpgradeRequest, _ *config.Config) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("apply staged binary on Windows requires the service helper")
	}
	// F2-UPGRADE-01 (2026-07-22): restart via systemd so the process picks
	// up the binary that HandleUpgrade already staged to disk.  We shell out
	// to systemctl in the background so this goroutine can return; systemd
	// will start the new binary as a fresh process.
	cmd := exec.Command("systemctl", "restart", "secagent.service")
	// Detach from the parent's stdin/stdout so systemctl does not race with
	// the agent's own log output.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("systemctl restart secagent: %w", err)
	}
	// Don't Wait() -- the current process is about to be killed by systemd
	// and we don't want to block the goroutine.
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
	AgentID    string `json:"-"`
	AgentToken string `json:"-"`
	CAPath     string `json:"-"`
}

// NucleiUpgradeRequest is the payload from the server's nuclei_upgrade command.
//
// The server sends this when the agent's heartbeat-reported nuclei_version does
// not match the Nacos-configured NUCLEI_VERSION. The agent downloads the zip
// from the internal nginx mirror (DownloadURL), extracts the nuclei binary, and
// swaps it in place -- no agent restart needed, since nuclei is invoked as a
// fresh subprocess per scan.
//
// Unlike agent_upgrade, the downloaded binary itself is NOT hash-signed: the
// download comes from a trusted internal mirror over HTTP and the command is
// Ed25519-signed (so a MitM cannot forge a nuclei_upgrade pointing at an
// attacker URL). Closing the HTTP-in-transit gap would require the server to
// pre-compute a sha256 and carry it in the signed payload; left as a future
// hardening step.
type NucleiUpgradeRequest struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	// CAPath is filled by main.go so a self-signed console CA (if the mirror
	// is served over TLS from the console host) is trusted. The internal nginx
	// mirror is plain HTTP, so this is usually unused.
	CAPath string `json:"-"`
}

// HandleNucleiUpgrade downloads the nuclei zip for req.Version, extracts the
// platform binary, and atomically swaps it into the install bin path. On
// success the caller re-detects the version and updates the heartbeat slot.
func HandleNucleiUpgrade(req NucleiUpgradeRequest, sendAck func(kind, version string, ok bool, err string)) error {
	log.Printf("[updater] downloading nuclei v%s from %s", req.Version, req.DownloadURL)

	if req.DownloadURL == "" {
		return ackFail(sendAck, "nuclei", req.Version, "missing download_url", fmt.Errorf("missing download_url - nuclei_upgrade requires a mirror URL"))
	}

	client, err := httpClient(req.CAPath)
	if err != nil {
		return ackFail(sendAck, "nuclei", req.Version, err.Error(), fmt.Errorf("build http client: %w", err))
	}
	resp, err := client.Get(req.DownloadURL)
	if err != nil {
		return ackFail(sendAck, "nuclei", req.Version, err.Error(), fmt.Errorf("download nuclei zip: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ackFail(sendAck, "nuclei", req.Version, fmt.Sprintf("HTTP %d", resp.StatusCode), fmt.Errorf("nuclei download returned status %d", resp.StatusCode))
	}

	body, err := readLimitedBody(resp.Body, maxNucleiDownloadBytes)
	if err != nil {
		return ackFail(sendAck, "nuclei", req.Version, err.Error(), fmt.Errorf("read nuclei zip: %w", err))
	}

	// Resolve the target install path the same way the nuclei runner does
	// (honors SECAGENT_HOME). This is where /opt/secagent/bin/nuclei lives.
	targetPath := nuclei.NewCLIRunner().BinaryPath
	if targetPath == "" {
		return ackFail(sendAck, "nuclei", req.Version, "could not resolve nuclei install path", fmt.Errorf("could not resolve nuclei install path"))
	}
	targetName := filepath.Base(targetPath) // "nuclei" on linux, "nuclei.exe" on windows

	if err := extractNucleiBinary(body, targetName, targetPath); err != nil {
		return ackFail(sendAck, "nuclei", req.Version, err.Error(), fmt.Errorf("extract nuclei binary: %w", err))
	}

	log.Printf("[updater] nuclei v%s installed at %s", req.Version, targetPath)
	if sendAck != nil {
		sendAck("nuclei", req.Version, true, "")
	}
	return nil
}

// extractNucleiBinary scans a zip body for the nuclei executable entry and
// atomically swaps it into targetPath. The projectdiscovery zip lays the
// binary at the archive root; we match by base name so a stray README/LICENSE
// is ignored. The write is tmp-file + rename so a crash mid-write cannot leave
// a half-written binary that would break the next scan.
func extractNucleiBinary(zipBody []byte, wantName, targetPath string) error {
	zipReader, err := zip.NewReader(bytes.NewReader(zipBody), int64(len(zipBody)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	var src *zip.File
	for _, f := range zipReader.File {
		if filepath.Base(f.Name) == wantName && !f.FileInfo().IsDir() {
			src = f
			break
		}
	}
	if src == nil {
		return fmt.Errorf("zip has no %q entry", wantName)
	}

	rc, err := src.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %q: %w", src.Name, err)
	}
	defer rc.Close()

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir bin dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".nuclei-upgrade-*")
	if err != nil {
		return fmt.Errorf("create staged binary: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, rc); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0o755); err != nil {
			return fmt.Errorf("chmod staged binary: %w", err)
		}
	}

	// Best-effort backup of the previous binary so a bad swap is recoverable.
	oldPath := targetPath + ".old"
	_ = os.Remove(oldPath)
	if _, err := os.Stat(targetPath); err == nil {
		if err := os.Rename(targetPath, oldPath); err != nil {
			return fmt.Errorf("backup current nuclei: %w", err)
		}
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Roll back to the previous binary if we kept one.
		if _, statErr := os.Stat(oldPath); statErr == nil {
			_ = os.Rename(oldPath, targetPath)
		}
		return fmt.Errorf("install nuclei: %w", err)
	}

	// F3-SELINUX: the staged file carries tmp_t; restorecon so systemd / the
	// scan subprocess can execve it. Best-effort: selinux may be disabled.
	if runtime.GOOS == "linux" {
		if err := exec.Command("restorecon", targetPath).Run(); err != nil {
			log.Printf("[updater] WARN: restorecon %s failed: %v (selinux may be disabled)", targetPath, err)
		}
	}
	return nil
}

// NucleiTemplatesUpdateRequest is the payload from the server's
// nuclei_templates_update command (rules page「同步 Nuclei 模板」button).
//
// The agent downloads the nuclei-templates zip from the internal mirror
// (DownloadURL) and extracts it into /opt/secagent/templates, replacing the
// previous bundle. The command is Ed25519-signed; the downloaded zip itself
// is not hash-verified (trusted internal mirror), mirroring nuclei_upgrade.
type NucleiTemplatesUpdateRequest struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	CAPath      string `json:"-"`
}

// HandleNucleiTemplatesUpdate downloads the templates zip, extracts it into a
// temp dir, and atomically swaps it into the nuclei templates directory. The
// old bundle is kept as a .old sibling for one cycle so a bad extract is
// recoverable. nuclei reads templates via -t <dir> on the next scan, so no
// restart is needed.
func HandleNucleiTemplatesUpdate(req NucleiTemplatesUpdateRequest, sendAck func(kind, version string, ok bool, err string)) error {
	log.Printf("[updater] downloading nuclei-templates v%s from %s", req.Version, req.DownloadURL)

	if req.DownloadURL == "" {
		return ackFail(sendAck, "nuclei_templates", req.Version, "missing download_url", fmt.Errorf("missing download_url - nuclei_templates_update requires a mirror URL"))
	}

	// nuclei templates can be large (tens of MB); allow a longer download.
	client, err := httpClient(req.CAPath)
	if err != nil {
		return ackFail(sendAck, "nuclei_templates", req.Version, err.Error(), fmt.Errorf("build http client: %w", err))
	}
	client.Timeout = 5 * time.Minute
	resp, err := client.Get(req.DownloadURL)
	if err != nil {
		return ackFail(sendAck, "nuclei_templates", req.Version, err.Error(), fmt.Errorf("download nuclei-templates zip: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ackFail(sendAck, "nuclei_templates", req.Version, fmt.Sprintf("HTTP %d", resp.StatusCode), fmt.Errorf("nuclei-templates download returned status %d", resp.StatusCode))
	}
	body, err := readLimitedBody(resp.Body, maxTemplatesDownloadBytes)
	if err != nil {
		return ackFail(sendAck, "nuclei_templates", req.Version, err.Error(), fmt.Errorf("read nuclei-templates zip: %w", err))
	}

	// Resolve the target templates dir the same way the nuclei runner does
	// (honors SECAGENT_HOME): /opt/secagent/templates.
	targetDir := nuclei.NewCLIRunner().TemplatesDir
	if targetDir == "" {
		return ackFail(sendAck, "nuclei_templates", req.Version, "could not resolve templates dir", fmt.Errorf("could not resolve nuclei templates dir"))
	}

	if err := swapTemplatesZip(body, targetDir); err != nil {
		return ackFail(sendAck, "nuclei_templates", req.Version, err.Error(), fmt.Errorf("install nuclei-templates: %w", err))
	}

	log.Printf("[updater] nuclei-templates v%s installed at %s", req.Version, targetDir)
	if sendAck != nil {
		sendAck("nuclei_templates", req.Version, true, "")
	}
	return nil
}

// swapTemplatesZip extracts the templates zip into a sibling temp dir, then
// atomically renames it over targetDir (keeping the previous dir as .old for
// one cycle). The projectdiscovery zip wraps everything in a single top-level
// directory (nuclei-templates-<ver>/); we strip that wrapper so categories
// (cves/, exposures/, ...) land directly under targetDir and nuclei's -t sees
// them without an extra path component.
func swapTemplatesZip(zipBody []byte, targetDir string) error {
	zipReader, err := zip.NewReader(bytes.NewReader(zipBody), int64(len(zipBody)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	// Detect a single top-level wrapper directory shared by all entries so we
	// can strip it. If entries do not share one prefix, extract as-is.
	topLevel := sharedTopLevelPrefix(zipReader.File)

	parent := filepath.Dir(targetDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("mkdir templates parent: %w", err)
	}
	staged := targetDir + ".new"
	// Start from a clean staged dir (a previous failed run may have left one).
	if err := os.RemoveAll(staged); err != nil {
		return fmt.Errorf("clean staged templates dir: %w", err)
	}
	if err := os.MkdirAll(staged, 0o755); err != nil {
		return fmt.Errorf("mkdir staged templates dir: %w", err)
	}

	written := 0
	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := f.Name
		if topLevel != "" {
			name = strings.TrimPrefix(name, topLevel)
		}
		name = filepath.Clean(name)
		// Reject zip-slip: no absolute paths, no ".." escaping the staged dir.
		if filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(filepath.Separator)) || name == ".." {
			continue
		}
		dest := filepath.Join(staged, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("create %s: %w", dest, err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			_ = rc.Close()
			_ = out.Close()
			return fmt.Errorf("write %s: %w", dest, err)
		}
		_ = rc.Close()
		_ = out.Close()
		written++
	}
	if written == 0 {
		return fmt.Errorf("zip contained no template files")
	}

	// Atomic-ish swap: keep the old bundle as .old for one cycle.
	oldDir := targetDir + ".old"
	_ = os.RemoveAll(oldDir)
	if _, statErr := os.Stat(targetDir); statErr == nil {
		if err := os.Rename(targetDir, oldDir); err != nil {
			return fmt.Errorf("backup current templates: %w", err)
		}
	}
	if err := os.Rename(staged, targetDir); err != nil {
		// Roll back to the previous bundle if we kept one.
		if _, statErr := os.Stat(oldDir); statErr == nil {
			_ = os.Rename(oldDir, targetDir)
		}
		return fmt.Errorf("swap templates dir: %w", err)
	}
	return nil
}

// sharedTopLevelPrefix returns the single top-level directory prefix shared by
// every entry (e.g. "nuclei-templates-10.4.6/"), or "" when entries do not
// share one. Used to strip the release wrapper so categories land at the root.
func sharedTopLevelPrefix(files []*zip.File) string {
	var prefix string
	for _, f := range files {
		idx := strings.Index(f.Name, "/")
		if idx < 0 {
			// A root-level file means there is no single wrapper dir.
			return ""
		}
		top := f.Name[:idx+1]
		if prefix == "" {
			prefix = top
		} else if top != prefix {
			return ""
		}
	}
	return prefix
}

// httpClient builds an *http.Client that trusts the configured CA (so
// self-signed console certs work) and has a 60s timeout (so a hung server
// can't block the rule-update goroutine forever). Mirrors the CA loading in
// comm/client.go Connect.
//
// G-P1-2 (V12 阶段 5.1): when caPath is configured but unreadable / invalid,
// this now returns an error instead of silently falling back to the system
// root CA. A silently-fallback client would let a self-signed console cert
// pass TLS validation to the WRONG trust anchor -- the agent would accept a
// forged mirror and install attacker-controlled binaries/rules.
func httpClient(caPath string) (*http.Client, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	if caPath == "" {
		return client, nil
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert %s: invalid PEM", caPath)
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}
	return client, nil
}

// HandleRuleUpdate downloads and hot-loads new vulnerability rules (no restart).
//
// P1-GO-2: verify the Ed25519 signature on the response body before loading the
// rules. Without this a MitM (default ws:// channel is plain!) could swap rule
// packs to hide real findings or trigger SSRF against the agent.
func HandleRuleUpdate(req RuleUpdateRequest, sendAck func(kind, version string, ok bool, err string)) error {
	log.Printf("[updater] downloading rule pack v%s", req.RuleVersion)

	if req.Signature == "" {
		return ackFail(sendAck, "rule", req.RuleVersion, "missing signature", fmt.Errorf("missing signature - rule_update requires Ed25519 signature"))
	}
	if crypto.PublicKey == nil {
		return ackFail(sendAck, "rule", req.RuleVersion, "server public key not configured", fmt.Errorf("server public key not configured - cannot verify rule update"))
	}

	// 修复(P1-1/P1-2)：用带 CA + 超时的 http.Client，凭证走 Authorization
	// header（与 WS 链路一致，不把 token 拼进 URL 落日志/抓包）。agent_id 走
	// query（非敏感，后端用它 + header token 做 validate_agent_token）。
	downloadURL := req.DownloadURL
	httpReq, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, err.Error(), fmt.Errorf("build download request: %w", err))
	}
	if req.AgentID != "" {
		q := httpReq.URL.Query()
		q.Set("agent_id", req.AgentID)
		httpReq.URL.RawQuery = q.Encode()
	}
	if req.AgentID != "" && req.AgentToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.AgentToken)
	}
	client, err := httpClient(req.CAPath)
	if err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, err.Error(), fmt.Errorf("build http client: %w", err))
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, err.Error(), fmt.Errorf("download rule pack: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ackFail(sendAck, "rule", req.RuleVersion, fmt.Sprintf("HTTP %d", resp.StatusCode), fmt.Errorf("download returned status %d", resp.StatusCode))
	}

	data, err := readLimitedBody(resp.Body, maxRuleDownloadBytes)
	if err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, err.Error(), fmt.Errorf("read rule pack: %w", err))
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, "invalid signature encoding", fmt.Errorf("invalid signature encoding: %w", err))
	}
	if !ed25519.Verify(crypto.PublicKey, data, sig) {
		return ackFail(sendAck, "rule", req.RuleVersion, "Ed25519 verification failed", fmt.Errorf("Ed25519 signature verification failed - rule pack rejected"))
	}

	if err := scan.LoadRules(data); err != nil {
		return ackFail(sendAck, "rule", req.RuleVersion, err.Error(), fmt.Errorf("load rules: %w", err))
	}

	log.Printf("[updater] rules v%s loaded", req.RuleVersion)
	// F-WSL (2026-07-21): the caller (main.go) records the new version
	// on the client so the next heartbeat reports it back.
	if sendAck != nil {
		sendAck("rule", req.RuleVersion, true, "")
	}
	return nil
}
