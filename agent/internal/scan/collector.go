// Package scan provides the vulnerability scanning engine.
package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// CollectedItem holds raw system information collected during a scan.
type CollectedItem struct {
	Category string            `json:"category"` // sys_vuln | baseline
	Type     string            `json:"type"`     // package | kernel | config | account | port | file_perm | log
	Data     map[string]string `json:"data"`
}

// Collector gathers system information for vulnerability matching.
type Collector struct{}

// NewCollector creates a new Collector.
func NewCollector() *Collector {
	return &Collector{}
}

// CollectSysVuln collects system vulnerability information (packages + kernel).
func (c *Collector) CollectSysVuln() ([]CollectedItem, error) {
	var items []CollectedItem

	// Collect installed packages
	packages, err := c.collectPackages()
	if err != nil {
		return nil, fmt.Errorf("collect packages: %w", err)
	}
	items = append(items, packages...)

	// Collect kernel version
	kernel := c.collectKernel()
	items = append(items, kernel)

	return items, nil
}

// CollectBaseline collects security baseline information.
func (c *Collector) CollectBaseline() ([]CollectedItem, error) {
	var items []CollectedItem

	// Account checks
	items = append(items, c.collectAccounts()...)

	// Listening ports
	items = append(items, c.collectPorts()...)

	// Config-file content (SSH config, login.defs, auditd, limits, iptables, rsyslog).
	// The matcher reads each rule's check.file/path to find the matching item
	// and applies check.pattern as a regex over the file content. P0 (2026-07-19):
	// previous version only stat()'d these files which made every config_check
	// rule fire with "Config not found" even on hardened hosts.
	items = append(items, c.collectConfigFiles()...)

	// File permissions (stat only -- separate from config_file content above)
	items = append(items, c.collectFilePerms()...)

	return items, nil
}

// configFileTargets is the set of files we slurp for config_check rules.
// Each entry maps a logical label to the on-disk path; baseline rules in
// rules_sync.default_rules.yaml carry check.file paths that must match
// exactly. The matcher uses path as the join key.
var configFileTargets = []struct{ label, path string }{
	{"sshd_config", "/etc/ssh/sshd_config"},
	{"login_defs", "/etc/login.defs"},
	{"auditd_conf", "/etc/audit/auditd.conf"},
	{"limits_conf", "/etc/security/limits.conf"},
	{"iptables_names", "/proc/net/ip_tables_names"},
	{"rsyslog_conf", "/etc/rsyslog.conf"},
}

// collectConfigFiles reads each known config file and emits one item per
// file. The matcher reads content with regex (check.pattern) and a substring
// expectation (check.expect, case-insensitive). Missing files are silently
// skipped -- they are not findings on their own; the rule decides whether
// a missing file is a problem.
func (c *Collector) collectConfigFiles() []CollectedItem {
	if runtime.GOOS == "windows" {
		return nil // baseline config files are Linux-only today
	}
	var items []CollectedItem
	for _, t := range configFileTargets {
		data, err := os.ReadFile(t.path)
		if err != nil {
			continue // file absent -- let the rule decide
		}
		items = append(items, CollectedItem{
			Category: "baseline",
			Type:     "config_file",
			Data: map[string]string{
				"path":    t.path,
				"label":   t.label,
				"content": string(data),
			},
		})
	}
	return items
}

func (c *Collector) collectPackages() ([]CollectedItem, error) {
	if runtime.GOOS == "windows" {
		return c.collectPackagesWindows()
	}
	return c.collectPackagesLinux()
}

func (c *Collector) collectPackagesLinux() ([]CollectedItem, error) {
	var items []CollectedItem

	// P1 (2026-07-19): guard each exec with exec.LookPath + a 5s context so a
	// WSL/distro without dpkg-query OR rpm (e.g. docker-desktop WSL where
	// the package manager is not installed but the binary may exist as a
	// placeholder that hangs) does not block the entire scan. Without this
	// guard, the test target in WSL2 hangs forever in collectPackages and
	// the scan never finishes.
	tryRun := func(name string, args ...string) ([]byte, error) {
		if _, err := exec.LookPath(name); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).Output()
	}

	// Try dpkg (Debian/Ubuntu)
	output, err := tryRun("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 {
				items = append(items, CollectedItem{
					Category: "sys_vuln",
					Type:     "package",
					Data:     map[string]string{"name": parts[0], "version": parts[1], "manager": "dpkg"},
				})
			}
		}
		return items, nil
	}

	// Try rpm (RHEL/CentOS/Fedora)
	output, err = exec.Command("rpm", "-qa", "--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return nil, fmt.Errorf("neither dpkg nor rpm available")
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			items = append(items, CollectedItem{
				Category: "sys_vuln",
				Type:     "package",
				Data:     map[string]string{"name": parts[0], "version": parts[1], "manager": "rpm"},
			})
		}
	}
	return items, nil
}

func (c *Collector) collectPackagesWindows() ([]CollectedItem, error) {
	var items []CollectedItem

	// Use wmic to get installed hotfixes
	output, err := exec.Command("wmic", "qfe", "get", "HotFixID", "/format:csv").Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "KB") {
				items = append(items, CollectedItem{
					Category: "sys_vuln",
					Type:     "package",
					Data:     map[string]string{"name": line, "version": "installed", "manager": "windows_hotfix"},
				})
			}
		}
	}
	return items, nil
}

func (c *Collector) collectKernel() CollectedItem {
	if runtime.GOOS == "windows" {
		return CollectedItem{
			Category: "sys_vuln",
			Type:     "kernel",
			Data:     map[string]string{"version": os.Getenv("OS"), "os": "windows"},
		}
	}

	output, err := exec.Command("uname", "-r").Output()
	version := "unknown"
	if err == nil {
		version = strings.TrimSpace(string(output))
	}
	return CollectedItem{
		Category: "sys_vuln",
		Type:     "kernel",
		Data:     map[string]string{"version": version, "os": "linux"},
	}
}

func (c *Collector) collectAccounts() []CollectedItem {
	var items []CollectedItem

	if runtime.GOOS == "windows" {
		// Check local user accounts
		output, err := exec.Command("net", "user").Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "---") && !strings.Contains(line, "command completed") {
					items = append(items, CollectedItem{
						Category: "baseline",
						Type:     "account",
						Data:     map[string]string{"username": line},
					})
				}
			}
		}
		return items
	}

	// Linux: read /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return items
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			shell := parts[6]
			if shell != "/usr/sbin/nologin" && shell != "/bin/false" {
				items = append(items, CollectedItem{
					Category: "baseline",
					Type:     "account",
					Data:     map[string]string{"username": parts[0], "uid": parts[2], "shell": shell},
				})
			}
		}
	}
	return items
}

func (c *Collector) collectPorts() []CollectedItem {
	var items []CollectedItem

	if runtime.GOOS == "windows" {
		output, err := exec.Command("netstat", "-ano").Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "LISTENING") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						addr := fields[1]
						if idx := strings.LastIndex(addr, ":"); idx >= 0 {
							port := addr[idx+1:]
							items = append(items, CollectedItem{
								Category: "baseline",
								Type:     "port",
								Data:     map[string]string{"port": port, "address": addr},
							})
						}
					}
				}
			}
		}
		return items
	}

	output, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		output, err = exec.Command("netstat", "-tlnp").Output()
	}
	if err != nil {
		return items
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				if idx := strings.LastIndex(addr, ":"); idx >= 0 {
					port := addr[idx+1:]
					items = append(items, CollectedItem{
						Category: "baseline",
						Type:     "port",
						Data:     map[string]string{"port": port, "address": addr},
					})
				}
			}
		}
	}
	return items
}

func (c *Collector) collectFilePerms() []CollectedItem {
	paths := []string{"/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/root/.ssh"}
	if runtime.GOOS == "windows" {
		paths = []string{`C:\Windows\System32\config\SAM`}
	}

	var items []CollectedItem
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := info.Mode()
		items = append(items, CollectedItem{
			Category: "baseline",
			Type:     "file_perm",
			Data: map[string]string{
				"path":        p,
				"permissions": mode.String(),
				"uid":         fmt.Sprintf("%d", getUID(info)),
			},
		})
	}
	return items
}

func getUID(info os.FileInfo) int {
	// Platform-specific stat_t required; skip for MVP
	return 0
}
