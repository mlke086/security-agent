package protection

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// fakeProbe implements Probe with deterministic values so we can exercise
// each threshold without making real syscalls. Only the fields each test
// actually needs are populated.
type fakeProbe struct {
	cpu     []float64
	cpuErr  error
	load    *load.AvgStat
	loadErr error
	mem     *mem.VirtualMemoryStat
	memErr  error
	disk    *disk.UsageStat
	diskErr error
}

func (f *fakeProbe) CPUPercent(_ context.Context, _ time.Duration, _ bool) ([]float64, error) {
	return f.cpu, f.cpuErr
}

func (f *fakeProbe) LoadAvg(_ context.Context) (*load.AvgStat, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.load, nil
}

func (f *fakeProbe) VirtualMemory(_ context.Context) (*mem.VirtualMemoryStat, error) {
	if f.memErr != nil {
		return nil, f.memErr
	}
	return f.mem, nil
}

func (f *fakeProbe) DiskUsage(_ context.Context, _ string) (*disk.UsageStat, error) {
	if f.diskErr != nil {
		return nil, f.diskErr
	}
	return f.disk, nil
}

func mustAvgLoad(load1 float64) *load.AvgStat {
	return &load.AvgStat{Load1: load1}
}

func mustMem(pct float64) *mem.VirtualMemoryStat {
	return &mem.VirtualMemoryStat{UsedPercent: pct}
}

func mustDisk(pct float64) *disk.UsageStat {
	return &disk.UsageStat{UsedPercent: pct}
}

func newMonitor(t Thresholds) *Monitor {
	m := NewMonitor(t, 4)
	m.Probe = &fakeProbe{}
	return m
}

func TestShouldPause_NoPressure(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	fp := m.Probe.(*fakeProbe)
	fp.cpu = []float64{30, 40, 50, 30}
	fp.load = mustAvgLoad(0.8)
	fp.mem = mustMem(40)
	fp.disk = mustDisk(50)

	d := m.ShouldPause(context.Background())
	if d.Pause {
		t.Fatalf("expected continue, got pause=%v reason=%s", d.Pause, d.Reason)
	}
}

func TestShouldPause_CPUHigh(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	m.Probe.(*fakeProbe).cpu = []float64{95, 92, 97, 96}
	d := m.ShouldPause(context.Background())
	if !d.Pause || d.Reason != ReasonCPUHigh {
		t.Fatalf("expected pause cpu_high, got pause=%v reason=%s", d.Pause, d.Reason)
	}
}

func TestShouldPause_LoadHigh(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	m.Probe.(*fakeProbe).cpu = []float64{10, 10, 10, 10}
	m.Probe.(*fakeProbe).load = mustAvgLoad(8.0) // 8/4 = 2.0/cpu, exceeds 1.20
	d := m.ShouldPause(context.Background())
	if !d.Pause || d.Reason != ReasonLoadHigh {
		t.Fatalf("expected pause load_high, got pause=%v reason=%s", d.Pause, d.Reason)
	}
}

func TestShouldPause_MemoryHigh(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	m.Probe.(*fakeProbe).cpu = []float64{5, 5, 5, 5}
	m.Probe.(*fakeProbe).mem = mustMem(95)
	d := m.ShouldPause(context.Background())
	if !d.Pause || d.Reason != ReasonMemoryFull {
		t.Fatalf("expected pause memory_full, got pause=%v reason=%s", d.Pause, d.Reason)
	}
}

func TestShouldPause_DiskHigh(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	m.Probe.(*fakeProbe).cpu = []float64{5, 5, 5, 5}
	m.Probe.(*fakeProbe).disk = mustDisk(96)
	d := m.ShouldPause(context.Background())
	if !d.Pause || d.Reason != ReasonDiskFull {
		t.Fatalf("expected pause disk_full, got pause=%v reason=%s", d.Pause, d.Reason)
	}
}

func TestShouldPause_ProbeErrorsAreFailOpen(t *testing.T) {
	m := newMonitor(DefaultThresholds())
	fp := m.Probe.(*fakeProbe)
	fp.cpuErr = errors.New("stat cpu fail")
	// ProbeError doesn't actually run -- ShouldPause() handles each probe
	// individually and only pauses when a successful reading exceeds a
	// threshold. Failed probes therefore don't cause a pause, matching the
	// design intent: a flaky probe should not bring scans to a halt.
	d := m.ShouldPause(context.Background())
	if d.Pause {
		t.Fatalf("probe error should not pause, got reason=%s", d.Reason)
	}
}

func TestProbeErrorHelper(t *testing.T) {
	d := ProbeError(errors.New("sample"))
	if d.Reason != ReasonProbeFail {
		t.Errorf("got reason=%s", d.Reason)
	}
	if d.Detail == "" {
		t.Errorf("expected non-empty detail")
	}
}

func TestCustomThresholdsAllowsExtremelyStrict(t *testing.T) {
	m := newMonitor(Thresholds{
		CPUSustainedPct: 10.0, // very strict: pause on anything > 10% CPU
	})
	m.Probe.(*fakeProbe).cpu = []float64{15, 15, 15, 15}
	d := m.ShouldPause(context.Background())
	if !d.Pause {
		t.Fatalf("expected pause with strict threshold, got %+v", d)
	}
}
