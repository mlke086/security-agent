package scan

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/security-agent/agent/internal/resource"
	"github.com/security-agent/agent/internal/protection"
	"github.com/security-agent/agent/internal/scan/nuclei"
)

// ScanEngine orchestrates a full scan: collect -> match -> report.
//
// Two engines are supported today:
//
//   - matcher : own rule-based CVE matcher (default; always available)
//   - nuclei  : os/exec wrapper around the nuclei CLI which carries the
//                projectdiscovery templates bundle. Requires the host to
//                have /opt/secagent/bin/nuclei (see packaging/install.sh).
//
// The console picks the engine per scan_task via the ``engine`` field on
// ScanCommand. Empty/``matcher`` falls back to the existing path so older
// consoles keep working.
type ScanEngine struct {
	collector *Collector
	matcher   *Matcher
	nuclei    *nuclei.CLIRunner // may be nil when nuclei binary is not installed
	Monitor   *resource.Monitor
	Protector *protection.Monitor // optional self-protection (P1 of docs/架构改造设计.md)
	mu        sync.Mutex

	// Callback for sending progress updates
	OnStep func(taskID, step, status, message string)
	// Callback for sending result batches
	OnResult func(taskID, hostname string, findings []Finding, batch int, isFinal bool)
	// Callback for sending task ack
	OnAck func(taskID string, accepted bool, reason string)

	// P1-GO-06 (2026-07-19): registry of in-flight scan cancel funcs so a
	// scan_cancel command from the server can interrupt a long-running scan.
	// Keyed by task_id. Acquire the cancel mutex before mutating.
	cancels   map[string]context.CancelFunc
	cancelMu  sync.Mutex
}

// NewScanEngine creates a new ScanEngine. nuclei is created lazily (only
// if its binary is present) so hosts without nuclei still work.
func NewScanEngine() *ScanEngine {
	e := &ScanEngine{
		collector: NewCollector(),
		matcher:   NewMatcher(),
		cancels:   make(map[string]context.CancelFunc),
	}
	if r := nuclei.NewCLIRunner(); r.Available() {
		e.nuclei = r
		log.Printf("[engine] nuclei backend available at %s", r.BinaryPath)
	} else {
		log.Printf("[engine] nuclei backend not installed; matcher-only mode")
	}
	return e
}

// Engine selects the scan backend. Empty == matcher for backward compat.
type Engine string

const (
	EngineMatcher Engine = "" // default; never wire "" explicitly
	EngineNuclei  Engine = "nuclei"
)

// ScanCommand is the payload received from server for a scan_command.
type ScanCommand struct {
	TaskID         string            `json:"task_id"`
	Modules        []string          `json:"modules"`
	ResourceLimit  map[string]int    `json:"resource_limit"`
	RuleVersion    string            `json:"rule_version"`
	Rules          []RuleDef         `json:"rules"`
	Policy         map[string]interface{} `json:"policy"`

	// Engine selects the scan backend. Empty == matcher.
	Engine Engine `json:"engine,omitempty"`

	// Nuclei-only fields, populated when Engine == EngineNuclei.
	NucleiTargets   []string          `json:"nuclei_targets,omitempty"`
	NucleiSeverity []string          `json:"nuclei_severity,omitempty"`
	NucleiTags      []string          `json:"nuclei_tags,omitempty"`
	NucleiTemplates []string          `json:"nuclei_templates,omitempty"`
	NucleiTimeout   int               `json:"nuclei_timeout_sec,omitempty"`
}

// RuleDef is a single vulnerability detection rule.
type RuleDef struct {
	ID       string    `json:"id"`
	Category string    `json:"category"`
	CVE      string    `json:"cve,omitempty"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Check    RuleCheck `json:"check"`
	Fix      string    `json:"fix,omitempty"`
}

// RuleCheck defines the detection logic for a rule.
type RuleCheck struct {
	Type    string `json:"type"`    // package_version | kernel_version | config_check
	Name    string `json:"name"`    // package name or config key
	Op      string `json:"op"`      // comparison operator
	Value   string `json:"value"`   // version or expected value
	File    string `json:"file"`    // config file path
	Pattern string `json:"pattern"` // regex pattern for config_check
	Expect  string `json:"expect"`  // expected value for config_check
}

// Finding represents a detected vulnerability. Same shape is reused for
// nuclei output -- the runner.go translates nuclei fields into this struct.
type Finding struct {
	Category  string   `json:"category"`
	CVE       string   `json:"cve,omitempty"`
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	Evidence  string   `json:"evidence"`
	Fix       string   `json:"fix,omitempty"`
	MatchType string   `json:"match_type,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// guardAgainstPressure is the P1 self-protection check. Returns (true, "")
// if the scan should proceed, or (false, reason) if the host should defer
// the scan and ack back to the console. Safe to call when e.Protector is nil
// -- it then always returns "proceed".
func (e *ScanEngine) guardAgainstPressure(taskID string) (bool, protection.Reason) {
	if e.Protector == nil {
		return true, protection.ReasonNone
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := e.Protector.ShouldPause(ctx)
	if !d.Pause {
		return true, protection.ReasonNone
	}
	log.Printf("[engine] task %s paused: %s", taskID, d.Reason)
	if e.OnStep != nil {
		e.OnStep(taskID, "protect", "paused", string(d.Reason))
	}
	return false, d.Reason
}


// Execute runs a scan. The dispatcher calls this in a goroutine.
func (e *ScanEngine) Execute(cmd ScanCommand, hostname string) {
	taskID := cmd.TaskID
	log.Printf("[engine] starting scan %s on %s (engine=%q)", taskID, hostname, cmd.Engine)

	// P1-GO-06 (2026-07-19): wrap the whole scan in a cancellable context so
	// the server can abort it mid-run via a scan_cancel command. The cancel
	// funcs are kept in e.cancels so CancelScan(taskID) can find them.
	_, cancel := context.WithCancel(context.Background())
	e.cancelMu.Lock()
	if e.cancels == nil {
		e.cancels = make(map[string]context.CancelFunc)
	}
	e.cancels[taskID] = cancel
	e.cancelMu.Unlock()
	defer func() {
		cancel()
		e.cancelMu.Lock()
		delete(e.cancels, taskID)
		e.cancelMu.Unlock()
	}()

	if e.OnAck != nil {
		e.OnAck(taskID, true, "")
	}

	// P1: self-protection -- defer the scan if the host is under heavy
	// pressure. The reason is recorded both in the agent log and the scan
	// step stream sent back to the console (so /hosts shows the reason).
	if proceed, reason := e.guardAgainstPressure(taskID); !proceed {
		// OnAck(false, ...) lets the console mark the scan as "paused" rather
		// than silently dropping it.
		if e.OnAck != nil {
			e.OnAck(taskID, false, string(reason))
		}
		if e.OnResult != nil {
			e.OnResult(taskID, hostname, nil, 1, true)
		}
		return
	}

	// Branch 1: Nuclei
	if cmd.Engine == EngineNuclei {
		e.runNuclei(cmd, hostname)
		return
	}

	// Branch 2: existing matcher. Kept verbatim from the previous
	// implementation (P1-GO-5 honoured: inline rules over cached rules).

	modules := make(map[string]bool)
	for _, m := range cmd.Modules {
		modules[m] = true
	}
	if len(modules) == 0 {
		modules["sys_vuln"] = true
		modules["baseline"] = true
	}

	// P1-GO-5: prefer rules delivered inline on the scan command over the
	// cached rule pack.
	resolveRules := func(inline []RuleDef) []RuleDef {
		if len(inline) > 0 {
			return inline
		}
		return GetRules()
	}

	var allFindings []Finding
	batch := 1

	// Step 1: System vulnerability collection
	if modules["sys_vuln"] {
		e.sendStep(taskID, "collect_packages", "running", "Collecting installed packages and kernel info")
		log.Printf("[engine] %s: collect_packages starting", taskID)
		log.Printf("[engine] %s: about to call CollectSysVuln", taskID)
		items, err := e.collector.CollectSysVuln()
		log.Printf("[engine] %s: CollectSysVuln returned err=%v items=%d", taskID, err, len(items))
		if err != nil {
			// A collection failure (e.g. no dpkg/rpm on a minimal host) must
			// NOT abort the whole scan: baseline can still run, and the final
			// is_final result must still be sent so the console's collect node
			// does not wait until its 1800s timeout. Mirror baseline's handling
			// -- record the failure as a step and fall through.
			e.sendStep(taskID, "collect_packages", "failed", err.Error())
		} else {
			e.sendStep(taskID, "collect_packages", "done", "Collected packages and kernel info")

			rules := resolveRules(cmd.Rules)
			if len(rules) > 0 {
				e.sendStep(taskID, "match_cve", "running", "Matching against CVE rules")
				findings := e.matcher.Match(items, rules)
				for i := range findings {
					findings[i].Category = "sys_vuln"
				}
				e.sendStep(taskID, "match_cve", "done", "CVE matching complete")
				e.sendResult(taskID, hostname, findings, batch, false)
				batch++
				allFindings = append(allFindings, findings...)
			}
		}
	}

	// Throttle check between modules
	if e.Monitor != nil && e.Monitor.IsThrottling() {
		e.sendStep(taskID, "throttle", "running", "Resource limit reached, pausing")
		time.Sleep(5 * time.Second)
	}

	// Step 3: Baseline collection
	if modules["baseline"] {
		e.sendStep(taskID, "baseline_check", "running", "Running security baseline checks")
		items, err := e.collector.CollectBaseline()
		if err != nil {
			e.sendStep(taskID, "baseline_check", "failed", err.Error())
		} else {
			rules := resolveRules(cmd.Rules)
			if len(rules) > 0 {
				findings := e.matcher.Match(items, rules)
				for i := range findings {
					findings[i].Category = "baseline"
				}
				e.sendResult(taskID, hostname, findings, batch, false)
				allFindings = append(allFindings, findings...)
				batch++
			}
			e.sendStep(taskID, "baseline_check", "done", "Baseline checks complete")
		}
	}

	// Step 4: Send final result
	e.sendStep(taskID, "report", "done", "Scan complete")
	e.sendResult(taskID, hostname, nil, batch, true)

	log.Printf("[engine] scan %s complete: %d findings", taskID, len(allFindings))
}

// runNuclei streams the project's nuclei templates through the bundled
// nuclei CLI. It is invoked when cmd.Engine == EngineNuclei and e.nuclei
// is non-nil. If nuclei is not installed we fall back to matcher (with a
// warning) so the operator's task is not lost.
func (e *ScanEngine) runNuclei(cmd ScanCommand, hostname string) {
	taskID := cmd.TaskID

	if e.nuclei == nil {
		e.sendStep(taskID, "nuclei", "skipped", "nuclei binary not installed; falling back to matcher")
		// Demote to matcher and recurse (one level only -- matcher won't
		// recurse back since cmd.Engine is empty now).
		cmd.Engine = EngineMatcher
		e.Execute(cmd, hostname)
		return
	}

	req := nuclei.Request{
		TaskID:      taskID,
		TemplateIDs: cmd.NucleiTemplates,
		Severity:    cmd.NucleiSeverity,
		Tags:        cmd.NucleiTags,
		Targets:     cmd.NucleiTargets,
		TimeoutSec:  cmd.NucleiTimeout,
	}

	e.sendStep(taskID, "nuclei", "running", "Launching nuclei scanner")
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutOrDefault(cmd.NucleiTimeout, 600))*time.Second)
	defer cancel()

	findingsCh, summary, err := e.nuclei.Run(ctx, req)
	if err != nil {
		e.sendStep(taskID, "nuclei", "failed", err.Error())
		e.sendResult(taskID, hostname, nil, 1, true)
		return
	}

	batch := 1
	var totalFindings int
	for f := range findingsCh {
		findings := []Finding{toFinding(f)}
		e.sendResult(taskID, hostname, findings, batch, false)
		batch++
		totalFindings++
	}

	e.sendStep(taskID, "nuclei", "done",
		"nuclei finished, "+itoa(totalFindings)+" findings (exit="+itoa(summary.ExitCode)+")")
	e.sendResult(taskID, hostname, nil, batch, true)

	log.Printf("[engine] nuclei scan %s complete: %d findings exit=%d",
		taskID, totalFindings, summary.ExitCode)
}

// toFinding converts a nuclei.Result into our internal Finding so the rest
// of the pipeline (WS, server, ES) doesn't need to know about nuclei.
func toFinding(r nuclei.Result) Finding {
	cve := r.CVE
	if cve == "" && r.TemplateID != "" && len(r.TemplateID) > 4 && r.TemplateID[:4] == "CVE-" {
		cve = r.TemplateID
	}
	return Finding{
		Category:  "nuclei",
		CVE:       cve,
		Name:      r.Name,
		Severity:  r.Severity,
		Evidence:  r.MatchedAt + "\n" + r.Evidence,
		MatchType: r.MatchType,
		Tags:      r.Tags,
	}
}

func timeoutOrDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// itoa is a tiny helper so we don't have to import strconv just to format
// step messages.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (e *ScanEngine) sendStep(taskID, step, status, message string) {
	if e.OnStep != nil {
		e.OnStep(taskID, step, status, message)
	}
}

func (e *ScanEngine) sendResult(taskID, hostname string, findings []Finding, batch int, isFinal bool) {
	if e.OnResult != nil {
		e.OnResult(taskID, hostname, findings, batch, isFinal)
	}
}

// HandleScanCommand parses a raw scan_command message and starts the scan.
func (e *ScanEngine) HandleScanCommand(payload json.RawMessage) {
	var cmd ScanCommand
	if err := json.Unmarshal(payload, &cmd); err != nil {
		log.Printf("[engine] failed to parse scan_command: %v", err)
		return
	}

	hostname, _ := os.Hostname()
	// Run scan in background goroutine
	go e.Execute(cmd, hostname)
}

// CancelScan triggers the cancel func registered for taskID. Safe to call
// from any goroutine. P1-GO-06 -- if the task is unknown (already finished
// or never started) this is a no-op, which is what the server expects when
// it sends a duplicate scan_cancel.
func (e *ScanEngine) CancelScan(taskID string) {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	if cancel, ok := e.cancels[taskID]; ok {
		log.Printf("[engine] cancel requested for task %s", taskID)
		cancel()
	} else {
		log.Printf("[engine] cancel for unknown/already-done task %s", taskID)
	}
}
