package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// Manifest is what the console side sends so the agent knows which nuclei
// templates bundle to use. The console's rules_sync pulls the latest from
// projectdiscovery/nuclei-templates and publishes via /api/v1/rules/sync.
type Manifest struct {
	Version     string `json:"version"`        // git rev / git tag / timestamp
	URL         string `json:"url"`            // tarball URL
	SHA256      string `json:"sha256"`         // sha256 of the downloaded tarball
	Total       int    `json:"total"`          // number of templates (diagnostics)
	GeneratedAt string `json:"generated_at"` // RFC3339
}

// ManifestName is the sentinel filename written under destDir after a
// successful install.
const ManifestName = "manifest.json"

// EnsureTemplates is idempotent: re-running is a no-op when the manifest
// hasn't changed. destDir should be a stable path on disk; we recommend
// <SECAGENT_HOME>/templates.
func EnsureTemplates(manifest Manifest, destDir string, client *http.Client) error {
	if manifest.URL == "" || manifest.SHA256 == "" {
		return errors.New("manifest missing url or sha256")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir templates dir: %w", err)
	}
	// Already-installed sentinel: skip download.
	sentinel := filepath.Join(destDir, ".v")
	if versionFile, err := os.ReadFile(sentinel); err == nil && string(bytesTrim(versionFile)) == manifest.Version {
		return nil
	}

	resp, err := client.Get(manifest.URL)
	if err != nil {
		return fmt.Errorf("download templates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download templates: HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "nuclei-tpl-*.tar.gz")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("read templates body: %w", err)
	}
	tmp.Close()
	got := hex.EncodeToString(hasher.Sum(nil))
	if !equalFold(got, manifest.SHA256) {
		return fmt.Errorf("templates sha256 mismatch: want %s got %s", manifest.SHA256, got)
	}

	if err := extractTarGz(tmpPath, destDir); err != nil {
		return err
	}
	if err := os.WriteFile(sentinel, []byte(manifest.Version), 0o644); err != nil {
		return fmt.Errorf("write version sentinel: %w", err)
	}
	return WriteManifest(destDir, manifest)
}

func extractTarGz(tarPath, destDir string) error {
	cmd := exec.Command("tar", "-xzf", tarPath, "-C", destDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("extract %s: %v (%s)", tarPath, err, string(out))
	}
	return nil
}

// WriteManifest persists the manifest to disk under destDir.
func WriteManifest(destDir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, ManifestName), b, 0o644)
}

// ReadManifest returns the previously persisted manifest or zero value.
func ReadManifest(destDir string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(destDir, ManifestName))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	return m, json.Unmarshal(b, &m)
}

// equalFold compares two hex strings case-insensitively.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
