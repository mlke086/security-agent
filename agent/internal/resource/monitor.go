// Package resource provides CPU and memory monitoring for resource-limited scans.
package resource

import (
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// Limit holds the resource usage limits.
type Limit struct {
	CPUPercent int `json:"cpu_percent"`
	MemPercent int `json:"mem_percent"`
}

// MetricsSample is one full host performance sample (需求① host_metrics payload).
// JSON tags match the server-side ES mapping in metrics_store.py
// (src/agents/metrics_store.py, index secagent-hostmetrics).
type MetricsSample struct {
	CPUPerc     float64 `json:"cpu_percent"`
	MemPerc     float64 `json:"mem_percent"`
	MemTotalMB  float64 `json:"mem_total_mb"`
	MemUsedMB   float64 `json:"mem_used_mb"`
	DiskPerc    float64 `json:"disk_percent"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskUsedGB  float64 `json:"disk_used_gb"`
	NetInKbps   float64 `json:"net_in_kbps"`
	NetOutKbps  float64 `json:"net_out_kbps"`
	Load1       float64 `json:"load1"`
}

// defaultMount returns the mount point to sample disk usage on.
func defaultMount() string {
	if runtime.GOOS == "windows" {
		return "C:"
	}
	return "/"
}

// Monitor samples CPU and memory usage at intervals.
type Monitor struct {
	mu      sync.Mutex
	limit   Limit
	current struct {
		cpu float64
		mem float64
	}
	// 需求①: disk sampling mount point (config_update metrics_mounts hot-updatable).
	mount string
	// 需求①: network-rate delta state (previous counter snapshot + timestamp).
	lastNet     net.IOCountersStat
	lastNetTime time.Time
	stop        chan struct{}
}

// NewMonitor creates a new resource monitor.
func NewMonitor(limit Limit) *Monitor {
	return &Monitor{
		limit: limit,
		mount: defaultMount(),
		stop:  make(chan struct{}),
	}
}

// UpdateMount hot-updates the disk sampling mount point (需求①).
// Empty input is ignored so a malformed config_update cannot disable sampling.
func (m *Monitor) UpdateMount(mount string) {
	if mount == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mount = mount
}

// Start begins periodic resource sampling.
func (m *Monitor) Start(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-ticker.C:
				m.sample()
			}
		}
	}()
}

// Stop stops the monitor.
func (m *Monitor) Stop() {
	close(m.stop)
}

// IsThrottling returns true if current usage exceeds the limit.
func (m *Monitor) IsThrottling() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.cpu > float64(m.limit.CPUPercent) ||
		m.current.mem > float64(m.limit.MemPercent)
}

// Usage returns the current CPU and memory usage percentages.
func (m *Monitor) Usage() (cpu, mem float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.cpu, m.current.mem
}

// UpdateLimit updates the resource limit at runtime.
func (m *Monitor) UpdateLimit(limit Limit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limit = limit
}

// Sample collects one full host-performance sample (需求①). Network throughput
// is derived from two IOCounters() snapshots divided by the elapsed interval
// (kbps, aggregate over all interfaces); load1 is 0 on Windows (gopsutil has
// no load support there). Every field is best-effort -- a failing probe leaves
// its zero value rather than failing the whole sample.
//
// Sample is safe to call concurrently with the throttling monitor: it shares
// the same mutex, so the Start() ticker and an external reporter (metrics
// package) can both drive sampling without racing.
func (m *Monitor) Sample() MetricsSample {
	m.mu.Lock()
	defer m.mu.Unlock()

	var s MetricsSample
	if v, err := mem.VirtualMemory(); err == nil && v != nil && v.Total > 0 {
		s.MemPerc = v.UsedPercent
		s.MemTotalMB = float64(v.Total) / 1024 / 1024
		s.MemUsedMB = float64(v.Used) / 1024 / 1024
	}
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		s.CPUPerc = percents[0]
	}
	if du, err := disk.Usage(m.mount); err == nil && du != nil && du.Total > 0 {
		s.DiskPerc = du.UsedPercent
		s.DiskTotalGB = float64(du.Total) / 1024 / 1024 / 1024
		s.DiskUsedGB = float64(du.Used) / 1024 / 1024 / 1024
	}
	now := time.Now()
	if counters, err := net.IOCounters(false); err == nil && len(counters) > 0 {
		c := counters[0]
		// First sample only stores the baseline (no delta yet); counter
		// resets (reboot/interface flap) would produce a bogus negative,
		// so a drop below the baseline is treated as "no delta this round".
		if !m.lastNetTime.IsZero() && c.BytesRecv >= m.lastNet.BytesRecv && c.BytesSent >= m.lastNet.BytesSent {
			secs := now.Sub(m.lastNetTime).Seconds()
			if secs > 0 {
				s.NetInKbps = float64(c.BytesRecv-m.lastNet.BytesRecv) * 8 / 1024 / secs
				s.NetOutKbps = float64(c.BytesSent-m.lastNet.BytesSent) * 8 / 1024 / secs
			}
		}
		m.lastNet = c
		m.lastNetTime = now
	}
	if la, err := load.Avg(); err == nil && la != nil {
		s.Load1 = la.Load1
	}
	return s
}

func (m *Monitor) sample() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// V13 P1-13: real sampling via gopsutil. The previous implementation
	// approximated CPU usage with NumGoroutine/GOMAXPROCS -- a number that
	// has nothing to do with actual CPU load, so IsThrottling never fired
	// meaningfully. cpu.Percent(0, false) is an instantaneous sample since
	// the last call (the ticker interval is the sampling window).
	if v, err := mem.VirtualMemory(); err == nil && v != nil && v.Total > 0 {
		m.current.mem = v.UsedPercent
	}
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		m.current.cpu = percents[0]
	}
}
