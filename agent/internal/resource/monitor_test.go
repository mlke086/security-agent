package resource

import (
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {	m := NewMonitor(Limit{CPUPercent: 50, MemPercent: 60})
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

// TestSample_ReturnsReasonableValues (需求①): Sample() 用真实 gopsutil 采集
// 完整指标。第一次调用网络差分为基线（0），其余字段应非负且数量级合理；
// 第二次调用产生非负网络差分。
func TestSample_ReturnsReasonableValues(t *testing.T) {
	m := NewMonitor(Limit{})

	s1 := m.Sample()
	if s1.CPUPerc < 0 || s1.CPUPerc > 100 {
		t.Errorf("cpu_percent %v out of range", s1.CPUPerc)
	}
	if s1.MemPerc < 0 || s1.MemPerc > 100 {
		t.Errorf("mem_percent %v out of range", s1.MemPerc)
	}
	if s1.MemTotalMB <= 0 {
		t.Errorf("mem_total_mb %v should be positive", s1.MemTotalMB)
	}
	if s1.MemUsedMB <= 0 {
		t.Errorf("mem_used_mb %v should be positive", s1.MemUsedMB)
	}
	if s1.DiskTotalGB <= 0 {
		t.Errorf("disk_total_gb %v should be positive (mount %q)", s1.DiskTotalGB, m.mount)
	}
	if s1.DiskPerc < 0 || s1.DiskPerc > 100 {
		t.Errorf("disk_percent %v out of range", s1.DiskPerc)
	}
	if s1.NetInKbps != 0 || s1.NetOutKbps != 0 {
		t.Errorf("first sample should record the net baseline only, got in=%v out=%v",
			s1.NetInKbps, s1.NetOutKbps)
	}
	if s1.Load1 < 0 {
		t.Errorf("load1 %v should be non-negative", s1.Load1)
	}

	// 第二次采样：网络差分非负（计数器只会增长；reset 时被差分逻辑吞掉）。
	time.Sleep(50 * time.Millisecond)
	s2 := m.Sample()
	if s2.NetInKbps < 0 || s2.NetOutKbps < 0 {
		t.Errorf("negative net delta: in=%v out=%v", s2.NetInKbps, s2.NetOutKbps)
	}
}

// TestUpdateMount (需求①): 热更新挂载点；空值被忽略。
func TestUpdateMount(t *testing.T) {
	m := NewMonitor(Limit{})
	m.UpdateMount("/data")
	if m.mount != "/data" {
		t.Errorf("mount not updated: %q", m.mount)
	}
	m.UpdateMount("")
	if m.mount != "/data" {
		t.Errorf("empty mount should be ignored, got %q", m.mount)
	}
}
