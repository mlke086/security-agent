package nuclei

import "testing"

// TestParseVersion covers the nuclei ``-version`` output shapes we expect to
// see, without shelling out to a real nuclei binary.
func TestParseVersion(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"v-prefixed", "Nuclei Engine Version: v3.11.0\n", "3.11.0"},
		{"bare", "3.11.0\n", "3.11.0"},
		{"with_banner", "some banner\nNuclei Engine Version: v3.4.5\nConfig: x", "3.4.5"},
		{"empty", "", ""},
		{"no_version", "nuclei development build\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseVersion(c.input); got != c.want {
				t.Errorf("parseVersion(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestDetectVersionEmptyPath(t *testing.T) {
	if got := DetectVersion(""); got != "" {
		t.Errorf("DetectVersion(\"\") = %q, want \"\"", got)
	}
}
