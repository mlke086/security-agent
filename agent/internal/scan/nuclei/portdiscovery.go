package nuclei

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// discoverListeningPorts runs ss -tlnpH to enumerate all TCP listening ports
// on this host. Falls back to parsing /proc/net/tcp when ss is unavailable.
// Returns a deduplicated port list (e.g. ["22", "8000", "9200", "8848"]).
//
// S-P1-3 (V12): the failure path now returns an error instead of silently
// yielding nil -- a bare-host scan with zero discovered ports would report
// "scan completed, 0 findings" and read as "no vulnerabilities" to the
// operator even though no template ever ran.
//
// Called by runner.go when a scan target is a bare hostname/IP (no URL scheme)
// so nuclei scans every real service instead of guessing 8 common ports.
func discoverListeningPorts() ([]string, error) {
	// Primary: ss -tlnpH (fast, no DNS, numeric ports)
	out, err := exec.Command("ss", "-tlnpH").Output()
	if err == nil && len(out) > 0 {
		return parseSSPorts(string(out)), nil
	}
	// Fallback: /proc/net/tcp
	raw, err2 := os.ReadFile("/proc/net/tcp")
	if err2 == nil {
		return parseProcNetTCP(string(raw)), nil
	}
	// Nothing works (minimal container images often lack both ss and
	// /proc/net/tcp). Surface the failure so the caller can log a
	// port_discovery_failed event instead of silently scanning nothing.
	return nil, fmt.Errorf("ss unavailable (%v) and /proc/net/tcp unreadable (%v)", err, err2)
}

// parseSSPorts extracts listening ports from "ss -tlnpH" output.
//
// Example line: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=937,fd=3))"
// We fish the 4th whitespace-separated token and grab the port after the last colon.
func parseSSPorts(output string) []string {
	seen := map[string]bool{}
	var ports []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3] // "0.0.0.0:22" or "[::]:6379"
		if idx := strings.LastIndex(addr, ":"); idx >= 0 {
			port := addr[idx+1:]
			if _, err := strconv.Atoi(port); err == nil && !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}
	return ports
}

// parseProcNetTCP extracts listening ports from /proc/net/tcp (hex format).
// Used as fallback when ss is not installed (e.g. minimal container images).
//
// Example line: "   0: 00000000:1F90 00000000:0000 0A ..."
// Local address is the 2nd field; port is hex in the last 4 chars after colon.
func parseProcNetTCP(raw string) []string {
	seen := map[string]bool{}
	var ports []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "sl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		localAddr := fields[1] // "00000000:1F90"
		if idx := strings.LastIndex(localAddr, ":"); idx >= 0 {
			hexPort := localAddr[idx+1:]
			if port, err := strconv.ParseUint(hexPort, 16, 16); err == nil {
				portStr := strconv.Itoa(int(port))
				if !seen[portStr] {
					seen[portStr] = true
					ports = append(ports, portStr)
				}
			}
		}
	}
	return ports
}

// filterTCPPorts keeps only ports that are likely to host HTTP/HTTPS services.
// Port 22 (SSH) is always excluded; the rest pass through.
// Callers are free to use the unfiltered list; this is a convenience.
// joinHostPort builds the "host:port" string for nuclei. It also handles
// IPv6 addresses via net.JoinHostPort (e.g. [::1]:80).
func joinHostPort(host, port string) string {
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

// intersectPorts returns the subset of discovered ports that the user
// explicitly listed. When “allowed“ is empty, the discovered set is
// returned unchanged so existing callers do not need to special-case
// the empty list.
func intersectPorts(discovered []string, allowed []int) []string {
	if len(allowed) == 0 {
		return discovered
	}
	want := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		want[strconv.Itoa(p)] = struct{}{}
	}
	out := discovered[:0:0]
	for _, p := range discovered {
		if _, ok := want[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

func filterTCPPorts(ports []string) []string {
	skip := map[string]bool{
		"22": true, // SSH not an HTTP service
	}
	var out []string
	for _, p := range ports {
		if !skip[p] {
			out = append(out, p)
		}
	}
	return out
}
