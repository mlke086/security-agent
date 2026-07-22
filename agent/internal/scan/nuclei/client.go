package nuclei

import (
	"context"
	"time"
)

// Request is the operator-issued nuclei scan request. Mirrors the scanCommand
// payload sent by the console over WS but only the fields nuclei cares about.
type Request struct {
	TaskID      string            // unique id, matches our ScanCommand.TaskID
	TemplateIDs []string          // -t list (e.g. ["cves/2024/CVE-2024-1234"]); empty = all
	Severity    []string          // -severity list (e.g. ["critical","high"])
	Tags        []string          // -tags (e.g. ["rce","auth-bypass"])
	Targets     []string          // hosts/CIDRs to scan
	TimeoutSec  int               // 0 = use runner default
	ExtraArgs   map[string]string // any extra -key=value flags the console wants to pass
}

// Result is one nuclei finding translated into our Finding shape. The
// engine.go -> matcher.Findings pipeline reuses the JSON tag set; nuclei raw
// JSONL output is parsed inside runner.go.
type Result struct {
	TemplateID    string
	Name          string
	Severity      string // info|low|medium|high|critical|unknown
	MatchedAt     string // URL / host:port
	CVE           string
	CWE           string
	Description   string
	Reference     string
	Tags          []string
	Evidence      string
	MatchType     string
}

// Summary is the closing record NucleiRunner emits when nuclei exits.
type Summary struct {
	TaskID     string
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
	Findings   []Result
}

// Runner is the narrow interface the rest of the scan package depends on. We
// swap implementations for tests (FakeRunner) without touching engine.go.
type Runner interface {
	// Run executes nuclei against req. findingsCh is fed asynchronously as the
	// subprocess prints JSONL lines; the func MUST close findingsCh before
	// returning so the caller can range over it safely.
	Run(ctx context.Context, req Request) (findingsCh <-chan Result, summary Summary, err error)

	// Available reports whether the underlying mechanism (CLI binary, SDK,
// etc.) is ready to run. install.sh uses this to decide whether to download
	// nuclei on first install.
	Available() bool
}
