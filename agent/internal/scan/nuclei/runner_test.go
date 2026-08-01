package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_NUCLEI_HELPER") == "1" {
		time.Sleep(150 * time.Millisecond)
		fmt.Fprintln(os.Stdout, `{"template-id":"CVE-2024-1234","info":{"name":"Delayed finding","severity":"high"},"matched-at":"http://target/","type":"http"}`)
		if os.Getenv("GO_NUCLEI_EXPECT_ARGS") == "1" {
			args := strings.Join(os.Args[1:], "\x00")
			for _, required := range []string{"-no-stdin", "-id\x00elasticsearch"} {
				if !strings.Contains(args, required) {
					fmt.Fprintf(os.Stderr, "missing expected args %q in %q\n", required, args)
					os.Exit(7)
				}
			}
			if strings.Contains(args, "-templates\x00elasticsearch") {
				fmt.Fprintln(os.Stderr, "template IDs were passed as template paths")
				os.Exit(7)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestCLIRunnerWaitsForProcessOutput(t *testing.T) {
	helper, err := os.Executable()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose executable mode bits to CLIRunner.Available")
	}
	if err != nil {
		t.Fatalf("locate test helper: %v", err)
	}
	t.Setenv("GO_WANT_NUCLEI_HELPER", "1")
	t.Setenv("GO_NUCLEI_EXPECT_ARGS", "1")

	runner := &CLIRunner{
		BinaryPath:        helper,
		TemplatesDir:      t.TempDir(),
		DefaultTimeoutSec: 5,
	}
	started := time.Now()
	findings, _, err := runner.Run(context.Background(), Request{
		TaskID:      "delayed-output",
		TemplateIDs: []string{"elasticsearch"},
		Targets:     []string{"http://target"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var got []Result
	for finding := range findings {
		got = append(got, finding)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Name != "Delayed finding" {
		t.Fatalf("finding name = %q, want Delayed finding", got[0].Name)
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("runner returned before subprocess output: %v", elapsed)
	}
}

func TestJoinHostPortLeavesProtocolDetectionToNuclei(t *testing.T) {
	cases := map[string]string{
		"192.168.80.101": "192.168.80.101:9200",
		"Rocky001":       "Rocky001:9200",
		"2001:db8::1":    "[2001:db8::1]:9200",
	}
	for host, want := range cases {
		if got := joinHostPort(host, "9200"); got != want {
			t.Errorf("joinHostPort(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestNucleiFindingUnmarshal checks that an NDJSON line from nuclei decodes
// into our internal finding shape. We don't shell out to nuclei here --
// the subprocess path is exercised by TestCLIRunnerAvailable (which only
// asserts on binary presence) and by the integration smoke-test in the
// dispatch flow.
func TestNucleiFindingUnmarshal(t *testing.T) {
	in := `{"template-id":"CVE-2024-1234","info":{"name":"Sample RCE","severity":"critical","description":"X","reference":"https://example","tags":["rce"]},"matched-at":"https://target:8443/","type":"http"}`

	scanner := bufio.NewScanner(bytes.NewReader([]byte(in)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !scanner.Scan() {
		t.Fatalf("scanner produced no lines")
	}
	line := bytes.TrimSpace(scanner.Bytes())

	var nff nucleiFinding
	if err := json.Unmarshal(line, &nff); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nff.Info.Name != "Sample RCE" {
		t.Errorf("Name: got %q want Sample RCE", nff.Info.Name)
	}
	if nff.Info.Severity != "critical" {
		t.Errorf("Severity: got %q want critical", nff.Info.Severity)
	}
	if nff.TemplateID != "CVE-2024-1234" {
		t.Errorf("TemplateID: got %q want CVE-2024-1234", nff.TemplateID)
	}
	if got := firstNonEmpty3(nff.MatchedAt, nff.Host, nff.IP); got != "https://target:8443/" {
		t.Errorf("MatchedAt fallback: got %q", got)
	}
}

func TestFirstNonEmpty3(t *testing.T) {
	cases := []struct{ a, b, c, want string }{
		{"", "", "c", "c"},
		{"", "b", "", "b"},
		{"a", "b", "c", "a"},
	}
	for _, c := range cases {
		if got := firstNonEmpty3(c.a, c.b, c.c); got != c.want {
			t.Errorf("firstNonEmpty3(%q,%q,%q) = %q want %q", c.a, c.b, c.c, got, c.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "b"); got != "b" {
		t.Errorf("got %q want b", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("got %q want a", got)
	}
}

func TestEqualFold(t *testing.T) {
	if !equalFold("ABCDEF", "abcdef") {
		t.Error("expected case-insensitive match")
	}
	if equalFold("ABC", "abcd") {
		t.Error("expected unequal lengths to fail")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		Version: "v9.9.9",
		URL:     "https://example.com/templates.tar.gz",
		SHA256:  "deadbeef",
		Total:   7,
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadManifest(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Version != m.Version || got.SHA256 != m.SHA256 || got.Total != m.Total {
		t.Errorf("roundtrip mismatch: %+v != %+v", got, m)
	}
}

// TestDecodeReferenceString covers the single-string reference field that
// most older / non-CVE templates use (one advisory URL).
func TestDecodeReferenceString(t *testing.T) {
	raw := json.RawMessage(`"https://example.com/advisory"`)
	got := decodeReference(raw)
	if got != "https://example.com/advisory" {
		t.Errorf("decodeReference(string) = %q, want https://example.com/advisory", got)
	}
}

// TestDecodeReferenceArray is the regression for the bug found
// 2026-07-31: CVE templates emit `reference:` as a YAML list, which nuclei
// serializes as a JSON array. The previous string-typed field made
// json.Unmarshal fail and silently dropped every such finding.
func TestDecodeReferenceArray(t *testing.T) {
	raw := json.RawMessage(`["https://example.com/a","https://example.com/b","https://example.com/c"]`)
	got := decodeReference(raw)
	want := "https://example.com/a\nhttps://example.com/b\nhttps://example.com/c"
	if got != want {
		t.Errorf("decodeReference(array) = %q, want %q", got, want)
	}
}

// TestDecodeReferenceEmpty handles the omitempty / absent case.
func TestDecodeReferenceEmpty(t *testing.T) {
	if got := decodeReference(nil); got != "" {
		t.Errorf("decodeReference(nil) = %q, want empty", got)
	}
	if got := decodeReference(json.RawMessage{}); got != "" {
		t.Errorf("decodeReference(empty) = %q, want empty", got)
	}
}

// TestNucleiFindingUnmarshalArrayReference verifies the end-to-end path:
// an NDJSON line with array reference unmarshals without error and
// stream() emits a Result whose Reference field is the newline-joined
// string. This is what was previously dropped silently.
func TestNucleiFindingUnmarshalArrayReference(t *testing.T) {
	in := `{"template-id":"CVE-2024-9999","info":{"name":"CVE X","severity":"high","reference":["https://a","https://b"]},"matched-at":"https://t:443/","type":"http"}`
	scanner := bufio.NewScanner(bytes.NewReader([]byte(in)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !scanner.Scan() {
		t.Fatalf("scanner produced no lines")
	}
	var nff nucleiFinding
	if err := json.Unmarshal(scanner.Bytes(), &nff); err != nil {
		t.Fatalf("array reference unmarshal: %v", err)
	}
	if got := decodeReference(nff.Info.Reference); got != "https://a\nhttps://b" {
		t.Errorf("decoded reference = %q, want newline-joined", got)
	}
}
