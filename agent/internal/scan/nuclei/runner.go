package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CLIRunner invokes the nuclei binary as a subprocess and parses its JSONL
// output (nuclei -json -silent). One CLIRunner per scan; cheap to create.
type CLIRunner struct {
	// BinaryPath is the absolute path to the nuclei executable. Default is
	// /opt/secagent/bin/nuclei which is what install.sh lays down.
	BinaryPath string

	// TemplatesDir is where nuclei reads templates from. install.sh keeps
	// this in sync with the latest sync-triggered bundle.
	TemplatesDir string

	// DefaultTimeoutSec is applied when req.TimeoutSec == 0.
	DefaultTimeoutSec int
}

// NewCLIRunner returns a runner with the default install paths.
func NewCLIRunner() *CLIRunner {
	return &CLIRunner{
		BinaryPath:       filepath.Join(defaultInstallDir(), "bin", "nuclei"),
		TemplatesDir:     filepath.Join(defaultInstallDir(), "templates"),
		DefaultTimeoutSec: 600,
	}
}

func defaultInstallDir() string {
	if d := os.Getenv("SECAGENT_HOME"); d != "" {
		return d
	}
	return "/opt/secagent"
}

// Available returns true if the nuclei binary is on disk and executable.
func (r *CLIRunner) Available() bool {
	if r.BinaryPath == "" {
		return false
	}
	info, err := os.Stat(r.BinaryPath)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}

type nucleiFinding struct {
	TemplateID    string   `json:"template-id"`
	TemplatePath  string   `json:"template-path"`
	Info          struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   string   `json:"reference"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type          string   `json:"type"`
	Host          string   `json:"host"`
	MatchedAt     string   `json:"matched-at"`
	MatchedLine   string   `json:"matched-line"`
	MatcherName   string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	IP            string   `json:"ip"`
}

// Run implements Runner.
func (r *CLIRunner) Run(ctx context.Context, req Request) (<-chan Result, Summary, error) {
	summary := Summary{TaskID: req.TaskID, StartedAt: time.Now().UTC()}

	if !r.Available() {
		return nil, summary, errors.New(
			"nuclei binary not available at " + r.BinaryPath +
				"; run packaging/install.sh to download it",
		)
	}

	args := []string{
		"-silent",                  // suppress progress output
		"-json",                    // one JSON object per line (NDJSON)
		"-no-stdin",                 // do not wait for interactive stdin
		"-t", r.TemplatesDir,        // template directory
	}
	if len(req.TemplateIDs) > 0 {
		args = append(args, "-templates", strings.Join(req.TemplateIDs, ","))
	}
	if len(req.Severity) > 0 {
		args = append(args, "-severity", strings.Join(req.Severity, ","))
	}
	if len(req.Tags) > 0 {
		args = append(args, "-tags", strings.Join(req.Tags, ","))
	}
	for _, t := range req.Targets {
		args = append(args, "-u", t)
	}
	for k, v := range req.ExtraArgs {
		args = append(args, "-"+k, v)
	}

	timeout := req.TimeoutSec
	if timeout <= 0 {
		timeout = r.DefaultTimeoutSec
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, r.BinaryPath, args...)
	// nuclei writes JSON lines to stdout and human-friendly progress to stderr.
	// We only consume stdout; stderr is forwarded to the agent log.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, summary, fmt.Errorf("open nuclei stdout: %w", err)
	}
	cmd.Stderr = &stderrWriter{prefix: "[nuclei]"}

	if err := cmd.Start(); err != nil {
		return nil, summary, fmt.Errorf("start nuclei: %w", err)
	}

	findings := make(chan Result, 32)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(findings)
		r.stream(cctx, stdout, req.TaskID, findings)
	}()

	go func() {
		wg.Wait()
		summary.FinishedAt = time.Now().UTC()
		if waitErr := cmd.Wait(); waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				summary.ExitCode = exitErr.ExitCode()
			}
		} else {
			summary.ExitCode = 0
		}
		// Walk findingsCh one last time to drain the slice. Channels are
		// closed by the streaming goroutine; we just need the elements.
		for f := range findings {
			summary.Findings = append(summary.Findings, f)
		}
	}()

	// Caller ranges over findings; close happens after subprocess exits.
	return findings, summary, nil
}

// stream reads nuclei NDJSON from r and pushes Results into out. If nuclei
// exits early with garbage in stdout we just stop emitting.
func (r *CLIRunner) stream(ctx context.Context, src io.Reader, taskID string, out chan<- Result) {
	scanner := bufio.NewScanner(src)
	// nuclei templates can be large; bump scanner buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := bytesTrim(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var nff nucleiFinding
		if err := json.Unmarshal(line, &nff); err != nil {
			log.Printf("[%s] bad finding line (ignored): %v", taskID, err)
			continue
		}
		out <- Result{
			TemplateID:  firstNonEmpty(nff.TemplateID, nff.TemplatePath),
			Name:        nff.Info.Name,
			Severity:    nff.Info.Severity,
			MatchedAt:   firstNonEmpty3(nff.MatchedAt, nff.Host, nff.IP),
			Description: nff.Info.Description,
			Reference:   nff.Info.Reference,
			Tags:        nff.Info.Tags,
			Evidence:    strings.Join(nff.ExtractedResults, "\n"),
			MatchType:   nff.Type,
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		log.Printf("[%s] nuclei stdout read error: %v", taskID, err)
	}
}

// stderrWriter forwards subprocess stderr to the agent logger. The default
// goes to os.Stderr; we just timestamp + tag each line so operators can
// distinguish agent log from nuclei log in a single stream.
type stderrWriter struct{ prefix string }

func (w *stderrWriter) Write(p []byte) (int, error) {
	log.Printf("%s %s", w.prefix, bytesTrim(p))
	return len(p), nil
}

func bytesTrim(b []byte) []byte {
	// strip trailing newline / whitespace; do not allocate.
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// firstNonEmpty3 picks the first non-empty of three strings; used when we
// have several candidate fields nuclei may populate (MatchedAt, Host, IP).
func firstNonEmpty3(a, b, c string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return c
}
