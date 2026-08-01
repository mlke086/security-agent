package nuclei

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"time"
)

// versionRe matches a semver-ish version token such as ``v3.11.0`` or
// ``3.11.0`` anywhere in the ``nuclei -version`` output. nuclei v3 prints a
// line like ``Nuclei Engine Version: v3.11.0``; we tolerate layout drift by
// just fishing for the first x.y.z token.
var versionRe = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

// parseVersion extracts the normalized nuclei version (leading ``v`` stripped)
// from ``nuclei -version`` output. Returns "" when no x.y.z token is present.
// Split out from DetectVersion so it is unit-testable without shelling out.
func parseVersion(output string) string {
	m := versionRe.FindStringSubmatch(output)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// DetectVersion runs ``<binaryPath> -version`` and returns the normalized
// version string (e.g. ``3.11.0``, leading ``v`` stripped). It returns an
// empty string when the binary is missing, fails to run, or its output does
// not contain a parseable version.
//
// Used by main.go at startup to seed the heartbeat's nuclei_version field and
// again after a nuclei_upgrade so the next heartbeat reports the new version.
// A 5s timeout bounds a hung binary so the agent never blocks on a tool that
// is only best-effort.
func DetectVersion(binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// -version makes nuclei print its version and exit 0; it does not touch
	// the network or run templates. -silent suppresses banner noise.
	cmd := exec.CommandContext(ctx, binaryPath, "-version", "-silent")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		// Some nuclei builds ignore -silent and still exit 0 with the banner on
		// stderr; others return non-zero while still printing the version. Try
		// to parse whatever output we got before giving up.
		if out.Len() == 0 {
			return ""
		}
	}
	return parseVersion(out.String())
}

// DetectDefaultVersion is a convenience wrapper that resolves the default
// install path (honoring SECAGENT_HOME) and reports its nuclei version.
// Returns "" when no nuclei binary is installed at the default path.
func DetectDefaultVersion() string {
	r := NewCLIRunner()
	if !r.Available() {
		return ""
	}
	return DetectVersion(r.BinaryPath)
}
