package scan

import "testing"

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
