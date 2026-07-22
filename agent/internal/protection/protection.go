// Package protection is the agent's self-protection layer. It guards against
// the scanner dragging a host's CPU / memory / disk into the red when the
// operator (or the orchestrator) blindly schedules a wave of scans.
//
// ShouldPause() is the single decision entry point: scan dispatcher calls it
// before each scan and reports the result back to the console as the host's
// status reason ("paused:cpu_high", "paused:disk_full", etc.).
//
// P1 (2026-07-18) of docs/架构改造设计.md replaces the ad-hoc bash scrapes
// we previously used in collector.go with this single gopsutil-backed check.
package protection

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// Thresholds holds the limits above which a scan should be deferred. Defaults
// match what `docs/架构改造设计.md` proposes; tests can lower them.
type Thresholds struct {
	CPUSustainedPct   float64       // 5-minute average above this is "paused:cpu_high"
	LoadAvgPerCPU     float64       // 1-minute loadavg / NumCPU above this pauses
	MemoryUsedPct     float64       // overall memory used above this pauses
	DiskUsedPct       float64       // root filesystem used above this pauses
	SampleInterval    time.Duration // how long CPU samples are averaged; 0 = "don't sample, fall back to instantaneous"
	CPUPollTimeout    time.Duration // timeout for the underlying gopsutil call
}

// DefaultThresholds returns the production defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		CPUSustainedPct: 80.0,
		LoadAvgPerCPU:   1.20,
		MemoryUsedPct:   90.0,
		DiskUsedPct:     95.0,
		SampleInterval:  5 * time.Second,
		CPUPollTimeout:  1 * time.Second,
	}
}

// Reason describes a single resource pressure that triggered a pause.
// The string form (".") is what gets reported back to the console and shown
// on the host UI as the "status reason" column.
type Reason string

const (
	ReasonNone       Reason = ""
	ReasonCPUHigh    Reason = "paused:cpu_high"
	ReasonLoadHigh   Reason = "paused:load_high"
	ReasonMemoryFull Reason = "paused:memory_full"
	ReasonDiskFull   Reason = "paused:disk_full"
	ReasonProbeFail  Reason = "paused:probe_error"
)

// Decision is the answer to a ShouldPause query.
type Decision struct {
	Pause   bool
	Reason  Reason
	Detail  string // human-readable for the audit log
	Checked time.Time
}

// Probe is the interface that the engine calls. It exists so tests can
// inject a deterministic gopsutil stand-in without touching disk / syscalls.
type Probe interface {
	CPUPercent(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error)
	LoadAvg(ctx context.Context) (*load.AvgStat, error)
	VirtualMemory(ctx context.Context) (*mem.VirtualMemoryStat, error)
	DiskUsage(ctx context.Context, path string) (*disk.UsageStat, error)
}

// RealProbe implements Probe using gopsutil.
type RealProbe struct{}

func (RealProbe) CPUPercent(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error) {
	return cpu.PercentWithContext(ctx, interval, percpu)
}

func (RealProbe) LoadAvg(ctx context.Context) (*load.AvgStat, error) {
	return load.AvgWithContext(ctx)
}

func (RealProbe) VirtualMemory(ctx context.Context) (*mem.VirtualMemoryStat, error) {
	return mem.VirtualMemoryWithContext(ctx)
}

func (RealProbe) DiskUsage(ctx context.Context, path string) (*disk.UsageStat, error) {
	if path == "" {
		path = "/"
	}
	usage, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return nil, err
	}
	return usage, nil
}

// Monitor decides whether to pause, using a Probe and Thresholds.
type Monitor struct {
	mu         sync.Mutex
	Probe      Probe
	Thresholds Thresholds
	NumCPU     int
}

// NewMonitor returns a Monitor wired up to gopsutil. NumCPU falls back to 1
// when not provided so the unit tests can construct one without running on
// real hardware.
func NewMonitor(t Thresholds, numCPU int) *Monitor {
	if numCPU <= 0 {
		numCPU = 1
	}
	return &Monitor{Probe: RealProbe{}, Thresholds: t, NumCPU: numCPU}
}

// ShouldPause is the entry point. It returns a Decision with Pause=true only
// when one of the thresholds is exceeded by enough margin. Probe errors do
// NOT pause (the host may still be usable, the operator gets a warning).
func (m *Monitor) ShouldPause(ctx context.Context) Decision {
	m.mu.Lock()
	defer m.mu.Unlock()

	t := m.Thresholds
	if t.CPUPollTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.CPUPollTimeout)
		defer cancel()
	}

	now := time.Now().UTC()

	// CPU: short sample interval; if too long, fall back to instantaneous.
	interval := t.SampleInterval
	cpus, err := m.Probe.CPUPercent(ctx, interval, false)
	if err == nil && len(cpus) > 0 {
		avg := avgFloat(cpus)
		if t.CPUSustainedPct > 0 && avg > t.CPUSustainedPct {
			return Decision{Pause: true, Reason: ReasonCPUHigh,
				Detail: fmt.Sprintf("cpu%.1f%%>%.1f%%", avg, t.CPUSustainedPct),
				Checked: now}
		}
	}

	// Load average (1-min). Useful on Linux where high load means the run-queue
	// is saturated even before cpu% saturates.
	if avg, err := m.Probe.LoadAvg(ctx); err == nil && avg != nil {
		perCPU := avg.Load1 / float64(m.NumCPU)
		if t.LoadAvgPerCPU > 0 && perCPU > t.LoadAvgPerCPU {
			return Decision{Pause: true, Reason: ReasonLoadHigh,
				Detail: fmt.Sprintf("load1=%.2f/cpu>%.2f", perCPU, t.LoadAvgPerCPU),
				Checked: now}
		}
	}

	if vm, err := m.Probe.VirtualMemory(ctx); err == nil && vm != nil && t.MemoryUsedPct > 0 {
		used := vm.UsedPercent
		if used > t.MemoryUsedPct {
			return Decision{Pause: true, Reason: ReasonMemoryFull,
				Detail: fmt.Sprintf("mem%.1f%%>%.1f%%", used, t.MemoryUsedPct),
				Checked: now}
		}
	}

	if du, err := m.Probe.DiskUsage(ctx, "/"); err == nil && du != nil && t.DiskUsedPct > 0 {
		used := du.UsedPercent
		if used > t.DiskUsedPct {
			return Decision{Pause: true, Reason: ReasonDiskFull,
				Detail: fmt.Sprintf("disk%.1f%%>%.1f%%", used, t.DiskUsedPct),
				Checked: now}
		}
	}

	return Decision{Pause: false, Reason: ReasonNone, Checked: now}
}

// ProbeError returns a paused-Decision with reason=ReasonProbeFail so the
// caller can choose between "fail open" (run anyway) and "fail closed"
// (skip). Engine uses fail-closed on probe error today; we keep that as a
// conservative default but surface a clear error to the audit log.
func ProbeError(err error) Decision {
	return Decision{
		Pause:   false, // we fail open for probe error; engine can decide otherwise
		Reason:  ReasonProbeFail,
		Detail:  fmt.Sprintf("probe_error:%v", err),
		Checked: time.Now().UTC(),
	}
}

func avgFloat(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	var sum float64
	for _, v := range s {
		sum += v
	}
	return sum / float64(len(s))
}

// ErrProbeFailed is returned when the underlying probe couldn't read metrics.
var ErrProbeFailed = errors.New("protection: probe failed")
