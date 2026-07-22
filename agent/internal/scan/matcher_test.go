package scan

import (
	"strings"
	"testing"
)

func TestMatcherPackageVersion(t *testing.T) {
	m := NewMatcher()
	rules := []RuleDef{{
		ID: "CVE-2024-TEST", Category: "sys_vuln", CVE: "CVE-2024-TEST",
		Name: "OpenSSH Buffer Overflow", Severity: "critical",
		Check: RuleCheck{Type: "package_version", Name: "openssh", Op: "lt", Value: "9.0"},
		Fix: "Upgrade openssh >= 9.0",
	}}
	items := []CollectedItem{{
		Category: "sys_vuln", Type: "package",
		Data: map[string]string{"name": "openssh", "version": "8.9", "manager": "dpkg"},
	}}

	findings := m.Match(items, rules)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", findings[0].Severity)
	}
}

func TestMatcherVersionNotVulnerable(t *testing.T) {
	m := NewMatcher()
	rules := []RuleDef{{
		ID: "CVE-2024-SAFE", Category: "sys_vuln", CVE: "CVE-2024-SAFE",
		Name: "Fixed Vuln", Severity: "high",
		Check: RuleCheck{Type: "package_version", Name: "nginx", Op: "lt", Value: "1.24"},
		Fix: "Upgrade nginx",
	}}
	items := []CollectedItem{{
		Category: "sys_vuln", Type: "package",
		Data: map[string]string{"name": "nginx", "version": "1.26", "manager": "dpkg"},
	}}

	findings := m.Match(items, rules)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (1.26 >= 1.24), got %d", len(findings))
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct{ a, op, b string; want bool }{
		{"1.0", "<", "2.0", true},
		{"2.0", ">", "1.0", true},
		{"1.0.0", "==", "1.0.0", true},
		{"1.2.3-1.el9", "<", "1.2.4", true},
		{"2:9.0", ">", "1:8.0", true},
		{"10", ">=", "9", true},
		// Cases the old cleanVersion+Atoi approach got wrong (epoch/revision/~ stripped):
		{"1:1.0", "<", "2:0.9", true},     // epoch 1 < epoch 2
		{"1.2.3~rc1", "<", "1.2.3", true}, // pre-release < release
		{"1.2.3-1", "<", "1.2.3-2", true}, // revision 1 < revision 2
		{"1.2.3-1.el9", "<", "1.2.3-2", true},
	}
	for _, tc := range tests {
		got := versionCompare(tc.a, tc.op, tc.b)
		if got != tc.want {
			t.Errorf("versionCompare(%q, %q, %q) = %v, want %v", tc.a, tc.op, tc.b, got, tc.want)
		}
	}
}


// --- config_check / config_file tests (P0 2026-07-19) ---

func TestMatcherConfigCheck_HardenedPasses(t *testing.T) {
	m := NewMatcher()
	rule := RuleDef{
		ID: "BL-001", Category: "baseline",
		Name: "SSH root login not disabled", Severity: "high",
		Check: RuleCheck{Type: "config_check", File: "/etc/ssh/sshd_config",
			Pattern: "^PermitRootLogin", Expect: "no"},
	}
	items := []CollectedItem{{
		Category: "baseline", Type: "config_file",
		Data: map[string]string{
			"path":    "/etc/ssh/sshd_config",
			"content": "# SSH config\nPermitRootLogin no\nPasswordAuthentication no\n",
		},
	}}
	if got := m.Match(items, []RuleDef{rule}); len(got) != 0 {
		t.Fatalf("hardened host should produce 0 findings, got %d: %+v", len(got), got)
	}
}

func TestMatcherConfigCheck_RuleLineMissing(t *testing.T) {
	m := NewMatcher()
	rule := RuleDef{
		ID: "BL-001", Category: "baseline",
		Name: "SSH root login not disabled", Severity: "high",
		Check: RuleCheck{Type: "config_check", File: "/etc/ssh/sshd_config",
			Pattern: "^PermitRootLogin", Expect: "no"},
	}
	items := []CollectedItem{{
		Category: "baseline", Type: "config_file",
		Data: map[string]string{
			"path":    "/etc/ssh/sshd_config",
			"content": "# PermitRootLogin yes\nPasswordAuthentication no\n",
		},
	}}
	got := m.Match(items, []RuleDef{rule})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (rule line missing), got %d", len(got))
	}
	if !strings.Contains(got[0].Evidence, "not found") {
		t.Errorf("evidence should say rule not found, got %q", got[0].Evidence)
	}
}

func TestMatcherConfigCheck_ValueMismatch(t *testing.T) {
	m := NewMatcher()
	rule := RuleDef{
		ID: "BL-002", Category: "baseline",
		Name: "PASS_MIN_LEN too short", Severity: "medium",
		Check: RuleCheck{Type: "config_check", File: "/etc/login.defs",
			Pattern: "^PASS_MIN_LEN", Expect: "8"},
	}
	items := []CollectedItem{{
		Category: "baseline", Type: "config_file",
		Data: map[string]string{
			"path":    "/etc/login.defs",
			"content": "PASS_MIN_LEN 5\n",
		},
	}}
	got := m.Match(items, []RuleDef{rule})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (value mismatch), got %d", len(got))
	}
	if !strings.Contains(got[0].Evidence, "PASS_MIN_LEN 5") {
		t.Errorf("evidence should quote the offending line, got %q", got[0].Evidence)
	}
}

func TestMatcherConfigCheck_WrongFilePathIgnored(t *testing.T) {
	m := NewMatcher()
	rule := RuleDef{
		ID: "BL-001", Category: "baseline",
		Check: RuleCheck{Type: "config_check", File: "/etc/ssh/sshd_config",
			Pattern: "^PermitRootLogin", Expect: "no"},
	}
	items := []CollectedItem{{
		Category: "baseline", Type: "config_file",
		Data: map[string]string{
			"path":    "/etc/login.defs",
			"content": "PermitRootLogin no\n",
		},
	}}
	if got := m.Match(items, []RuleDef{rule}); len(got) != 0 {
		t.Errorf("path mismatch must not match, got %d findings", len(got))
	}
}

func TestMatcherConfigCheck_CommentedLineNotCounted(t *testing.T) {
	m := NewMatcher()
	rule := RuleDef{
		ID: "BL-001", Category: "baseline",
		Check: RuleCheck{Type: "config_check", File: "/etc/ssh/sshd_config",
			Pattern: "^PermitRootLogin", Expect: "no"},
	}
	items := []CollectedItem{{
		Category: "baseline", Type: "config_file",
		Data: map[string]string{
			"path":    "/etc/ssh/sshd_config",
			"content": "# PermitRootLogin no\n",
		},
	}}
	got := m.Match(items, []RuleDef{rule})
	if len(got) != 1 {
		t.Fatalf("commented rule should be reported as missing, got %d findings", len(got))
	}
}
