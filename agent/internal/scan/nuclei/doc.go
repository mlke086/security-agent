// Package nuclei wraps the externally-installed Nuclei CLI scanner.
//
// We invoke `nuclei` as a subprocess (os/exec) rather than importing the
// heavyweight nuclei/v3 Go SDK. This keeps our agent binary small and lets the
// console push a fresh nuclei + nuclei-templates bundle without re-linking the
// agent. The trade-off is that the host must have a nuclei binary available --
// the install script (packaging/install.sh) downloads the matching release
// into /opt/secagent/bin/nuclei on first install.
//
// Input  : a JSON-encoded "scan command" the operator issues via the console.
// Output : a stream of Finding values (see engine.go) sent over the existing
//          scan_result WS message plus a final empty "is_final" batch.
//
// See ./client.go for the Runner interface and ./runner.go for the default
// CLI-backed implementation. ./templates.go covers the nuclei-templates
// download/cache that the console side triggers via /api/v1/rules/sync.
package nuclei
