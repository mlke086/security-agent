// Package scan provides the vulnerability scanning engine.
package scan

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	accounts := c.collectAccounts()
	items = append(items, accounts...)

	// Port checks
	ports := c.collectPorts()
	items = append(items, ports...)

	// Password policy
	pwdPolicy := c.collectPasswordPolicy()
	items = append(items, pwdPolicy...)

	// File permissions
	filePerms := c.collectFilePerms()
	items = append(items, filePerms...)

	// Logging config
	logConfig := c.collectLogConfig()
	items = append(items, logConfig...)

	return items, nil
}

func (c *Collector) collectPackages() ([]CollectedItem, error) {
	if runtime.GOOS == "windows" {
		return c.collectPackagesWindows()
	}
	return c.collectPackagesLinux()
}

func (c *Collector) collectPackagesLinux() ([]CollectedItem, error) {
	var items []CollectedItem

	// Try dpkg (Debian/Ubuntu)
	output, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
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

func (c *Collector) collectPasswordPolicy() []CollectedItem {
	if runtime.GOOS == "windows" {
		return nil
	}

	var items []CollectedItem
	// Read /etc/login.defs for password policy
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return items
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			items = append(items, CollectedItem{
				Category: "baseline",
				Type:     "password_policy",
				Data:     map[string]string{"key": parts[0], "value": parts[1]},
			})
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

func (c *Collector) collectLogConfig() []CollectedItem {
	var items []CollectedItem

	if runtime.GOOS == "windows" {
		return items
	}

	// Check if rsyslog or journald configs exist
	for _, p := range []string{"/etc/rsyslog.conf", "/etc/systemd/journald.conf"} {
		if _, err := os.Stat(p); err == nil {
			items = append(items, CollectedItem{
				Category: "baseline",
				Type:     "log_config",
				Data:     map[string]string{"config_file": p, "present": "true"},
			})
		}
	}
	return items
}

func getUID(info os.FileInfo) int {
	// Platform-specific stat_t required; skip for MVP
	return 0
}
