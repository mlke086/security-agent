package scan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Matcher compares collected system data against vulnerability rules.
type Matcher struct{}

// NewMatcher creates a new Matcher.
func NewMatcher() *Matcher {
	return &Matcher{}
}

// Match compares collected items against a set of rules and returns findings.
func (m *Matcher) Match(items []CollectedItem, rules []RuleDef) []Finding {
	var findings []Finding

	for _, rule := range rules {
		for _, item := range items {
			if !m.ruleApplies(rule, item) {
				continue
			}
			finding, matched := m.matchItem(rule, item)
			if matched {
				findings = append(findings, finding)
				break // One match per rule is enough
			}
		}
	}
	return findings
}

func (m *Matcher) ruleApplies(rule RuleDef, item CollectedItem) bool {
	return rule.Category == "baseline" && item.Category == "baseline" ||
		rule.Category == "sys_vuln" && item.Category == "sys_vuln"
}

func (m *Matcher) matchItem(rule RuleDef, item CollectedItem) (Finding, bool) {
	switch rule.Check.Type {
	case "package_version":
		return m.matchPackageVersion(rule, item)
	case "kernel_version":
		return m.matchKernelVersion(rule, item)
	case "config_check":
		return m.matchConfigCheck(rule, item)
	default:
		return Finding{}, false
	}
}

func (m *Matcher) matchPackageVersion(rule RuleDef, item CollectedItem) (Finding, bool) {
	if item.Type != "package" {
		return Finding{}, false
	}
	pkgName := item.Data["name"]
	pkgVersion := item.Data["version"]
	ruleName := rule.Check.Name
	ruleOp := rule.Check.Op
	ruleValue := rule.Check.Value

	if pkgName != ruleName {
		return Finding{}, false
	}

	if !versionCompare(pkgVersion, ruleOp, ruleValue) {
		return Finding{}, false
	}

	return Finding{
		Category: rule.Category,
		CVE:      rule.CVE,
		Name:     rule.Name,
		Severity: rule.Severity,
		Evidence: fmt.Sprintf("Package %s version %s %s %s", pkgName, pkgVersion, ruleOp, ruleValue),
		Fix:      rule.Fix,
	}, true
}

func (m *Matcher) matchKernelVersion(rule RuleDef, item CollectedItem) (Finding, bool) {
	if item.Type != "kernel" {
		return Finding{}, false
	}
	kernelVer := item.Data["version"]
	ruleName := rule.Check.Name
	ruleOp := rule.Check.Op
	ruleValue := rule.Check.Value

	if ruleName != "" && ruleName != "kernel" && !strings.Contains(kernelVer, ruleName) {
		return Finding{}, false
	}

	if !versionCompare(kernelVer, ruleOp, ruleValue) {
		return Finding{}, false
	}

	return Finding{
		Category: rule.Category,
		CVE:      rule.CVE,
		Name:     rule.Name,
		Severity: rule.Severity,
		Evidence: fmt.Sprintf("Kernel version %s %s %s", kernelVer, ruleOp, ruleValue),
		Fix:      rule.Fix,
	}, true
}

func (m *Matcher) matchConfigCheck(rule RuleDef, item CollectedItem) (Finding, bool) {
	if item.Type != "password_policy" && item.Type != "file_perm" && item.Type != "log_config" && item.Type != "account" {
		return Finding{}, false
	}

	pattern := rule.Check.Pattern
	expect := rule.Check.Expect

	// For config checks, we check if the collected data matches the pattern
	// If we're looking for a specific config key, check if it exists with expected value
	dataKey := rule.Check.Name
	if dataKey == "" {
		// Use pattern to determine what we're looking for
		dataKey = pattern
	}

	value, exists := item.Data[dataKey]
	if !exists {
		// Try to find by pattern in all data fields
		for k, v := range item.Data {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(k) || re.MatchString(v) {
				value = v
				exists = true
				break
			}
		}
	}

	if !exists && expect != "" {
		return Finding{
			Category: rule.Category,
			CVE:      rule.CVE,
			Name:     rule.Name,
			Severity: rule.Severity,
			Evidence: fmt.Sprintf("Config %s not found (expected %s)", pattern, expect),
			Fix:      rule.Fix,
		}, true
	}
	// Config not found and no expectation set - skip (not a finding)

	// Check if value matches expectation
	if expect != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(expect)) {
		return Finding{
			Category: rule.Category,
			CVE:      rule.CVE,
			Name:     rule.Name,
			Severity: rule.Severity,
			Evidence: fmt.Sprintf("Config %s=%s (expected %s)", dataKey, value, expect),
			Fix:      rule.Fix,
		}, true
	}

	return Finding{}, false
}

// versionCompare compares two version strings with an operator.
func versionCompare(v1, op, v2 string) bool {
	cmp := compareVersions(v1, v2)
	switch op {
	case "<", "lt":
		return cmp < 0
	case "<=", "le":
		return cmp <= 0
	case ">", "gt":
		return cmp > 0
	case ">=", "ge":
		return cmp >= 0
	case "=", "==", "eq":
		return cmp == 0
	case "!=", "ne":
		return cmp != 0
	default:
		return cmp < 0 // Default to "<"
	}
}

// compareVersions compares two version strings using dpkg-style version
// comparison (epoch:upstream-revision). This correctly handles epochs
// ("2:9.0" > "1:8.0"), pre-release suffixes ("1.2.3~rc1" < "1.2.3"), and
// distro revisions ("1.2.3-1.el9" vs "1.2.3-2"), which a naive dot-split +
// Atoi approach gets wrong.
// Returns -1 if a<b, 0 if a==b, 1 if a>b.
func compareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := compareVersionParts(ua, ub); c != 0 {
		return c
	}
	return compareVersionParts(ra, rb)
}

// splitVersion splits a version into (epoch, upstream, revision).
// "1:2.3.4-1.el9" -> (1, "2.3.4", "1.el9"); "1.2.3" -> (0, "1.2.3", "").
func splitVersion(v string) (epoch int, upstream, revision string) {
	upstream = v
	if idx := strings.Index(v, ":"); idx >= 0 {
		epoch, _ = strconv.Atoi(v[:idx])
		upstream = v[idx+1:]
	}
	if idx := strings.LastIndex(upstream, "-"); idx >= 0 {
		revision = upstream[idx+1:]
		upstream = upstream[:idx]
	}
	return epoch, upstream, revision
}

// compareVersionParts implements the dpkg upstream/revision comparison:
// alternating non-digit and digit chunks. Non-digit chunks compare char by
// char ('~' sorts before everything, including end-of-string); digit chunks
// compare numerically (empty == "0").
func compareVersionParts(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		na := nonDigitPrefix(a)
		nb := nonDigitPrefix(b)
		if c := compareNonDigit(a[:na], b[:nb]); c != 0 {
			return c
		}
		a, b = a[na:], b[nb:]
		da := digitPrefix(a)
		db := digitPrefix(b)
		ia, _ := strconv.Atoi(a[:da])
		ib, _ := strconv.Atoi(b[:db])
		if ia != ib {
			if ia < ib {
				return -1
			}
			return 1
		}
		a, b = a[da:], b[db:]
	}
	return 0
}

func nonDigitPrefix(s string) int {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return i
}

func digitPrefix(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// compareNonDigit compares two non-digit strings char by char. '~' sorts
// before everything (including end-of-string); other chars by ASCII.
func compareNonDigit(a, b string) int {
	la, lb := len(a), len(b)
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	for i := 0; i < maxLen; i++ {
		var ca, cb byte
		if i < la {
			ca = a[i]
		}
		if i < lb {
			cb = b[i]
		}
		va, vb := charOrder(ca), charOrder(cb)
		if va != vb {
			if va < vb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func charOrder(c byte) int {
	if c == 0 {
		return 0
	}
	if c == '~' {
		return -1
	}
	return int(c)
}
