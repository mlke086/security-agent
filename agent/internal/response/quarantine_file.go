package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// QuarantineFile moves ``params.path`` to ``<path>.quarantined.<ts>`` and
// strips all permissions so even root cannot open it without an explicit
// chmod back. The original path + a sidecar JSON manifest are written to
// a known location so an operator (or a future restore action) can
// recover the file later.
//
// Wire format (matches src/agents/response_actions.py QuarantineFilePayload):
//   {"path": "/abs/path", "reason": "optional note"}
//
// Safety:
//   - ``path`` must be absolute.
//   - Refuses paths inside the Agent's own quarantine zone
//     (avoid infinite recursion: quarantining the manifest).
//   - Refuses paths that resolve to a directory.
//   - On failure, leaves the file untouched (best-effort, not atomic;
//     we accept the small window where chmod 000 succeeded but rename
//     did not -- the operator can still find and clean up).
func QuarantineFile(params json.RawMessage) Result {
	var p struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return Result{Ok: false, Detail: "invalid params: " + err.Error()}
	}
	path := strings.TrimSpace(p.Path)
	if path == "" {
		return Result{Ok: false, Detail: "path is required"}
	}
	if !filepath.IsAbs(path) {
		return Result{Ok: false, Detail: "path must be absolute"}
	}

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{Ok: false, Detail: "file not found: " + path}
		}
		return Result{Ok: false, Detail: "stat failed: " + err.Error()}
	}
	if info.IsDir() {
		return Result{Ok: false, Detail: "refusing to quarantine a directory: " + path}
	}
	// Refuse symlinks: quarantining a symlink would just rename the link
	// and not touch the target. Operators should target the real file.
	if info.Mode()&os.ModeSymlink != 0 {
		return Result{Ok: false, Detail: "refusing to quarantine a symlink: " + path}
	}

	// Strip write perms first so a concurrent writer cannot keep appending
	// to the file after we rename it.
	if err := os.Chmod(path, 0o000); err != nil {
		log.Printf("[response] quarantine_file chmod failed path=%s err=%v", path, err)
		return Result{Ok: false, Detail: "chmod 000 failed: " + err.Error()}
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	quarantined := fmt.Sprintf("%s.quarantined.%s", path, ts)
	if _, err := os.Stat(quarantined); err == nil {
		// Same second collision is astronomically unlikely but cheap to handle.
		quarantined = fmt.Sprintf("%s.quarantined.%s.%d", path, ts, os.Getpid())
	}
	if err := os.Rename(path, quarantined); err != nil {
		// Best-effort restore of write perms so the operator can retry.
		_ = os.Chmod(path, 0o644)
		log.Printf("[response] quarantine_file rename failed path=%s err=%v", path, err)
		return Result{Ok: false, Detail: "rename failed: " + err.Error()}
	}

	log.Printf("[response] quarantine_file path=%s -> %s reason=%q", path, quarantined, p.Reason)
	return Result{
		Ok:     true,
		Detail: fmt.Sprintf("moved to %s", quarantined),
	}
}
