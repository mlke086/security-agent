package monitor

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Sink is the integration point the monitor uses to ship snapshots to
// the server. The production wiring is ``client.SendMonitorEvent`` in
// ``agent/cmd/agent/main.go``; tests pass a recording fake.
type Sink interface {
	Send(s Snapshot)
}

// SinkFunc adapts a plain function to the Sink interface. Useful when
// the production client already exposes a method with a different
// signature (e.g. takes ``interface{}``) -- the agent main wraps the
// call into a closure here rather than adding a method to the comm
// client just for this one use.
type SinkFunc func(Snapshot)

// Send implements Sink.
func (f SinkFunc) Send(s Snapshot) { f(s) }

// Monitor is the scheduler that periodically asks the Lister for a
// fresh Snapshot and hands it to the Sink. One Monitor per Agent
// process; safe to Start / Stop from any goroutine.
type Monitor struct {
	mu        sync.Mutex
	lister    Lister
	sink      Sink
	interval  time.Duration
	maxN      int
	stopCh    chan struct{}
	stoppedCh chan struct{}
	started   atomic.Bool
}

// New returns a Monitor that polls every ``interval`` and caps each
// snapshot at ``maxN`` processes (use 0 / <=0 for DefaultMaxProcesses).
//
// ``sink`` may be nil for tests that drive Snapshot() directly; in
// production main.go always wires client.SendMonitorEvent.
func New(lister Lister, sink Sink, interval time.Duration, maxN int) *Monitor {
	if maxN <= 0 {
		maxN = DefaultMaxProcesses
	}
	return &Monitor{
		lister:    lister,
		sink:      sink,
		interval:  interval,
		maxN:      maxN,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
}

// Start launches the polling goroutine. Idempotent: a second Start
// after Stop is a programming error and is logged + ignored.
func (m *Monitor) Start(ctx context.Context) {
	if !m.started.CompareAndSwap(false, true) {
		log.Println("[monitor] Start called twice; ignoring")
		return
	}
	go m.run(ctx)
}

// Stop signals the run loop to exit and waits for it to finish.
// Safe to call multiple times; safe to call before Start (no-op).
func (m *Monitor) Stop() {
	if !m.started.Load() {
		return
	}
	m.mu.Lock()
	select {
	case <-m.stopCh:
		m.mu.Unlock()
		return
	default:
	}
	close(m.stopCh)
	m.mu.Unlock()
	<-m.stoppedCh
}

func (m *Monitor) run(ctx context.Context) {
	defer close(m.stoppedCh)
	// Take one snapshot immediately so the console has data the
	// instant the agent connects, instead of waiting for the first
	// tick (could be 30s of blank "no data").
	m.tick(ctx)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

func (m *Monitor) tick(ctx context.Context) {
	// Bound the per-tick work so a wedged /proc does not stall the
	// next tick. The cap is generous: 5x interval is enough for any
	// realistic host, even one with a slow disk-based /proc.
	cctx, cancel := context.WithTimeout(ctx, m.interval*5)
	defer cancel()
	snap, err := collect(cctx, m.lister, m.interval, m.maxN)
	if err != nil {
		log.Printf("[monitor] collect failed: %v", err)
		return
	}
	if m.sink == nil {
		return
	}
	m.sink.Send(snap)
}

// Snapshot is exposed for tests that want a one-shot read without
// running the full ticker. Production code should call Start / Stop.
func (m *Monitor) Snapshot(ctx context.Context) (Snapshot, error) {
	return collect(ctx, m.lister, m.interval, m.maxN)
}
