package scan

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCollectorSysVuln(t *testing.T) {
	c := NewCollector()
	items, err := c.CollectSysVuln()
	if err != nil {
		t.Skipf("skipping (no package manager): %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least some packages or kernel info")
	}
	// Verify all items have required fields
	for _, item := range items {
		if item.Type != "package" && item.Type != "kernel" {
			t.Errorf("unexpected item type: %s", item.Type)
		}
		if item.Data["name"] == "" && item.Type == "package" {
			t.Error("package item missing name")
		}
	}
}

func TestCollectorBaseline(t *testing.T) {
	c := NewCollector()
	items, err := c.CollectBaseline()
	if err != nil {
		t.Fatalf("CollectBaseline: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least some baseline items")
	}
	for _, item := range items {
		if item.Category != "baseline" {
			t.Errorf("expected baseline category, got %s", item.Category)
		}
	}
}


// TestCollectorConfigFiles_Hardened covers the P0 (2026-07-19) fix: collector
// must slurp sshd_config / login.defs etc. as full text, not just stat()
// them. Otherwise every config_check rule fires "Config not found" on a
// hardened host -- the bug that motivated the rewrite.
func TestCollectorConfigFiles_Hardened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("baseline config-file collection is Linux-only")
	}
	dir := t.TempDir()

	// Rewrite configFileTargets to point at temp dir so the test is hermetic.
	orig := configFileTargets
	defer func() { configFileTargets = orig }()
	configFileTargets = []struct{ label, path string }{
		{"sshd_config", dir + "/sshd_config"},
		{"login_defs", dir + "/login_defs"},
		{"auditd_conf", dir + "/auditd_conf"},
		{"limits_conf", dir + "/limits_conf"},
	}
	mustWrite(t, dir+"/sshd_config",
		"# OpenBSD sshd config\nPermitRootLogin no\nPasswordAuthentication no\n")
	mustWrite(t, dir+"/login_defs",
		"PASS_MIN_LEN 12\nPASS_MAX_DAYS 90\n")
	mustWrite(t, dir+"/auditd_conf",
		"log_format = ENRICHED\n")
	mustWrite(t, dir+"/limits_conf",
		"* hard core 0\n")

	c := NewCollector()
	items, err := c.CollectBaseline()
	if err != nil {
		t.Fatalf("CollectBaseline: %v", err)
	}
	var got []CollectedItem
	for _, item := range items {
		if item.Type == "config_file" {
			got = append(got, item)
		}
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 config_file items, got %d", len(got))
	}
	byPath := map[string]CollectedItem{}
	for _, it := range got {
		byPath[it.Data["path"]] = it
	}
	if !strings.Contains(byPath[dir+"/sshd_config"].Data["content"], "PermitRootLogin no") {
		t.Error("sshd_config content missing")
	}
	if !strings.Contains(byPath[dir+"/login_defs"].Data["content"], "PASS_MIN_LEN 12") {
		t.Error("login.defs content missing")
	}
}

func TestCollectorConfigFiles_MissingFilesAreFine(t *testing.T) {
	dir := t.TempDir()
	orig := configFileTargets
	defer func() { configFileTargets = orig }()
	configFileTargets = []struct{ label, path string }{
		{"sshd_config", dir + "/sshd_config"},
		{"login_defs", dir + "/login_defs"},
	}

	c := NewCollector()
	items2, err := c.CollectBaseline()
	if err != nil {
		t.Fatalf("CollectBaseline: %v", err)
	}
	var count int
	for _, item := range items2 {
		if item.Type == "config_file" {
			count++
		}
	}
	if count != 0 {
		t.Errorf("expected 0 config_file items (no files present), got %d", count)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
