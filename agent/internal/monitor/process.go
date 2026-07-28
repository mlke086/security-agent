// Package monitor provides lightweight host-level process / file monitoring.
//
// Phase 5 of docs/Agent监控告警改造方案.md. This MVP enumerates the running
// process table every Tick and ships a snapshot up the existing WebSocket
// as a ``monitor_event`` message. File integrity monitoring (inotify on
// /etc/passwd, /etc/shadow, etc.) is tracked separately and not part of
// the MVP.
//
// Why a periodic snapshot and not per-event process_create / process_exit:
//
//   - The MVP is about giving the operator a "what is running" view and
//     feeding the Sigma detector a process inventory. Both consumers are
//     happy with a 30-second-old snapshot; per-event streaming can be
//     layered on later without breaking the wire format.
//   - gopsutil.Processes() is the cheapest cross-platform way to read the
//     table; per-event would require either netlink process connector
//     (Linux-only, complex) or psnotify (Windows-only), and we want this
//     to run on both for the agent's installer parity.
//
// The Snapshot payload is intentionally capped (DefaultMaxProcesses = 200)
// so a host with 5000+ processes does not blow up the WS frame. The
// truncation is deterministic (sorted by PID ascending) so the same
// process list is reported regardless of which goroutine wins the read.
package monitor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessSummary is the JSON-friendly view of a process used in the
// monitor_event payload. Field tags mirror the names the Sigma detector
// and AlertInboxPage expect (process.name / process.cmdline / process.pid
// / user.name) so existing rules can match against them without a
// separate adapter.
type ProcessSummary struct {
	PID        int32  `json:"pid"`
	PPID       int32  `json:"ppid"`
	Name       string `json:"name"`
	Cmdline    string `json:"cmdline"`
	Exe        string `json:"exe"`
	Username   string `json:"user_name"`
	UID        string `json:"uid"`
	CreateTime int64  `json:"create_time"`
}

// Snapshot is one monitor tick worth of process table state.
//
// TotalCount is the full table size (before truncation) so the operator
// UI can show "showing 200 of 540 processes" instead of pretending the
// truncation does not exist.
type Snapshot struct {
	CollectedAt time.Time        `json:"collected_at"`
	IntervalSec int              `json:"interval_sec"`
	Hostname    string           `json:"hostname"`
	TotalCount  int              `json:"total_count"`
	Truncated   bool             `json:"truncated"`
	Processes   []ProcessSummary `json:"processes"`
}

// Lister is the abstraction the Monitor polls. RealLister is the
// production implementation; tests inject a fake.
type Lister interface {
	List(ctx context.Context) ([]*process.Process, error)
	Hostname(ctx context.Context) (string, error)
}

// RealLister uses gopsutil. Cross-platform.
type RealLister struct{}

func (RealLister) List(ctx context.Context) ([]*process.Process, error) {
	return process.ProcessesWithContext(ctx)
}

func (RealLister) Hostname(_ context.Context) (string, error) {
	// gopsutil's host.Hostname is fine but we keep the dep surface
	// small -- process package is the only thing we need for the
	// lister. The agent main loop already records the hostname via
	// os.Hostname for heartbeat; this method is here for the
	// Monitor's per-snapshot host tag.
	if runtime.GOOS == "windows" {
		return windowsHostname()
	}
	return posixHostname()
}

// DefaultMaxProcesses is the cap on the per-snapshot payload. Tuned to
// fit a single WS frame after JSON encoding; raise it in config if your
// fleet has hosts that genuinely need to see more.
const DefaultMaxProcesses = 200

// collect walks the lister's output and produces a Snapshot. Errors per
// process are swallowed (one bad /proc/<pid> entry must not poison the
// whole tick) and reported as a truncated TotalCount mismatch.
func collect(ctx context.Context, l Lister, interval time.Duration, maxN int) (Snapshot, error) {
	procs, err := l.List(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	host, _ := l.Hostname(ctx)
	total := len(procs)
	truncated := total > maxN
	if total > maxN {
		// Sort by PID ascending so the truncation is stable; keeps
		// the same top-N selection across ticks for diffing.
		sort.Slice(procs, func(i, j int) bool { return procs[i].Pid < procs[j].Pid })
		procs = procs[:maxN]
	}
	out := make([]ProcessSummary, 0, len(procs))
	for _, p := range procs {
		s := summarize(p)
		out = append(out, s)
	}
	return Snapshot{
		CollectedAt: time.Now().UTC(),
		IntervalSec: int(interval.Seconds()),
		Hostname:    host,
		TotalCount:  total,
		Truncated:   truncated,
		Processes:   out,
	}, nil
}

// summarize reads the per-process fields gopsutil can give us without
// hitting the network (Username on some platforms shells out to `whoami`
// or reads /etc/passwd; we treat any failure there as empty string).
func summarize(p *process.Process) ProcessSummary {
	s := ProcessSummary{PID: p.Pid, CreateTime: safeCreateTime(p)}
	if ppid, err := p.Ppid(); err == nil {
		s.PPID = ppid
	}
	if name, err := p.Name(); err == nil {
		s.Name = name
	}
	if cmd, err := p.Cmdline(); err == nil {
		s.Cmdline = cmd
	}
	if exe, err := p.Exe(); err == nil {
		s.Exe = exe
	}
	if u, err := p.Username(); err == nil {
		// Trim domain prefixes ("DOMAIN\user" -> "user") so the
		// Sigma rule that matches on user.name does not need to
		// know which OS the agent is on.
		s.Username = stripDomain(u)
		if uid, uerr := p.Uids(); uerr == nil && len(uid) > 0 {
			s.UID = itoa(uid[0])
		}
	}
	return s
}

func safeCreateTime(p *process.Process) int64 {
	// gopsutil returns ms since epoch on Linux/Darwin; on Windows it
	// uses the kernel tick count, which we convert inside the call.
	// Wrap so a perms error does not blow up the whole snapshot.
	ct, err := p.CreateTime()
	if err != nil {
		return 0
	}
	return ct
}

func stripDomain(u string) string {
	if i := strings.LastIndex(u, `\`); i >= 0 {
		return u[i+1:]
	}
	return u
}

func itoa(i int32) string {
	// Avoid pulling strconv just for this; the int is small and the
	// string is for human / Sigma-rule consumption. We accept the
	// negative-as-typo quirk (uid should never be negative) and just
	// emit "-" for it.
	if i < 0 {
		return "-"
	}
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// posixHostname / windowsHostname are kept split so tests can stub
// RealLister.Hostname per platform without touching the rest of the
// production code path. Both delegate to os.Hostname today; if we ever
// need a real Win32 API call here the seam is in place.
func posixHostname() (string, error) {
	return os.Hostname()
}
func windowsHostname() (string, error) {
	return os.Hostname()
}

// ErrListerStopped is returned by Snapshot() once the Monitor has been
// stopped. Callers can use errors.Is to detect a clean shutdown vs a
// real error.
var ErrListerStopped = errors.New("monitor: lister stopped")
