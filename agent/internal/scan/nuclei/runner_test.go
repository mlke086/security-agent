package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

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
