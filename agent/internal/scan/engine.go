package scan

import (
	"os"
	"encoding/json"
	"time"

	"github.com/security-agent/agent/internal/resource"
	"log"
	"sync"
)

// ScanEngine orchestrates a full scan: collect -> match -> report.
type ScanEngine struct {
	collector *Collector
	matcher   *Matcher
	Monitor   *resource.Monitor
	mu        sync.Mutex

	// Callback for sending progress updates
	OnStep  func(taskID, step, status, message string)
	// Callback for sending result batches
	OnResult func(taskID, hostname string, findings []Finding, batch int, isFinal bool)
	// Callback for sending task ack
	OnAck    func(taskID string, accepted bool, reason string)
}

// NewScanEngine creates a new ScanEngine.
func NewScanEngine() *ScanEngine {
	return &ScanEngine{
		collector: NewCollector(),
		matcher:   NewMatcher(),
	}
}

// ScanCommand is the payload received from server for a scan_command.
type ScanCommand struct {
	TaskID        string            `json:"task_id"`
	Modules       []string          `json:"modules"`
	ResourceLimit map[string]int    `json:"resource_limit"`
	RuleVersion   string            `json:"rule_version"`
	Rules         []RuleDef         `json:"rules"`
	Policy        map[string]interface{} `json:"policy"`
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

// Finding represents a detected vulnerability.
type Finding struct {
	Category string `json:"category"`
	CVE      string `json:"cve,omitempty"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Fix      string `json:"fix,omitempty"`
}

// Execute runs a full scan based on the scan command.
func (e *ScanEngine) Execute(cmd ScanCommand, hostname string) {
	taskID := cmd.TaskID
	log.Printf("[engine] starting scan %s on %s", taskID, hostname)

	// Ack the task
	if e.OnAck != nil {
		e.OnAck(taskID, true, "")
	}

	modules := make(map[string]bool)
	for _, m := range cmd.Modules {
		modules[m] = true
	}
	if len(modules) == 0 {
		modules["sys_vuln"] = true
		modules["baseline"] = true
	}

	// P1-GO-5: prefer rules delivered inline on the scan command over the
	// cached rule pack. Without this, scan_command fails to produce findings
	// whenever rule_update has not been received yet (the typical case).
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
		items, err := e.collector.CollectSysVuln()
		if err != nil {
			e.sendStep(taskID, "collect_packages", "failed", err.Error())
			return
		}
		e.sendStep(taskID, "collect_packages", "done", "Collected packages and kernel info")

		// Step 2: Match against CVE rules
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
			// Match against baseline rules
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


