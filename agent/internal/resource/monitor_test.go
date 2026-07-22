package resource

import (
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	if m == nil {
		t.Fatal("NewMonitor returned nil")
	}
	if m.limit.CPUPercent != 50 || m.limit.MemPercent != 60 {
		t.Error("limit not set correctly")
	}
	if m.stop == nil {
		t.Error("stop channel is nil")
	}
}

func TestIsThrottling_BelowLimit(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.current.cpu = 30
	m.current.mem = 40
	if m.IsThrottling() {
		t.Error("should not throttle when below limit")
	}
}

func TestIsThrottling_CPUOver(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.current.cpu = 51
	m.current.mem = 40
	if !m.IsThrottling() {
		t.Error("should throttle when CPU over limit")
	}
}

func TestIsThrottling_MemOver(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.current.cpu = 30
	m.current.mem = 61
	if !m.IsThrottling() {
		t.Error("should throttle when memory over limit")
	}
}

func TestUsage(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.current.cpu = 42.5
	m.current.mem = 33.3
	cpu, mem := m.Usage()
	if cpu != 42.5 || mem != 33.3 {
		t.Errorf("Usage() = (%v, %v), want (42.5, 33.3)", cpu, mem)
	}
}

func TestUpdateLimit(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.UpdateLimit(Limit{CPUPercent: 30, MemPercent: 40})
	if m.limit.CPUPercent != 30 || m.limit.MemPercent != 40 {
		t.Error("UpdateLimit did not update values")
	}
}

func TestStartStop(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.Start(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	m.Stop()
	// After stop, sample goroutine should exit cleanly
	cpu, mem := m.Usage()
	// Just verify we get valid numbers, not NaN
	if cpu < 0 || cpu > 100 {
		t.Errorf("CPU %v out of range", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("Mem %v out of range", mem)
	}
}

func TestSample_UpdatesValues(t *testing.T) {
	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
	m.sample()
	cpu, mem := m.Usage()
	if cpu < 0 || cpu > 100 {
		t.Errorf("CPU %v out of range after sample", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("Mem %v out of range after sample", mem)
	}
}
