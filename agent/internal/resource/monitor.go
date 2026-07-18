// Package resource provides CPU and memory monitoring for resource-limited scans.
package resource

import (
	"runtime"
	"sync"
	"time"
)

// Limit holds the resource usage limits.
type Limit struct {
	CPUPercent int `json:"cpu_percent"`
	MemPercent int `json:"mem_percent"`
}

// Monitor samples CPU and memory usage at intervals.
type Monitor struct {
	mu      sync.Mutex
	limit   Limit
	current struct {
		cpu float64
		mem float64
	}
	stop chan struct{}
}

// NewMonitor creates a new resource monitor.
func NewMonitor(limit Limit) *Monitor {
	return &Monitor{
		limit: limit,
		stop:  make(chan struct{}),
	}
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

func (m *Monitor) sample() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Memory: percentage of system total
	totalMem := float64(memStats.Sys)
	allocMem := float64(memStats.Alloc)
	if totalMem > 0 {
		m.current.mem = (allocMem / totalMem) * 100
	}

	// CPU: rough approximation via goroutine count vs GOMAXPROCS
	// In production, use gopsutil or /proc/stat sampling
	numGoroutine := runtime.NumGoroutine()
	numCPU := runtime.GOMAXPROCS(0)
	if numCPU > 0 {
		m.current.cpu = float64(numGoroutine) / float64(numCPU*4) * 100
		if m.current.cpu > 100 {
			m.current.cpu = 100
		}
	}
}
