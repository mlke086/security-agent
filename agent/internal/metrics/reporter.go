// Package metrics periodically samples host performance and reports it
// over the WebSocket as ``host_metrics`` (需求① Agent 性能监控).
//
// Design contrast with the offline queue: ``scan_result`` is reliable
// delivery (queued in SQLite while disconnected), whereas host metrics are
// high-frequency time-series data -- replaying a stale backlog after a
// reconnect floods the server with worthless points. So the reporter uses
// the client's ephemeral send path (send only while connected, drop
// otherwise). The sampling interval is independent from the heartbeat:
// heartbeats carry version/online semantics at ~30s, metrics default to 15s.
package metrics

import (
	"context"
	"time"

	"github.com/security-agent/agent/internal/comm"
	"github.com/security-agent/agent/internal/resource"
)

// DefaultIntervalSec is the fallback sampling interval when config does not
// provide one (config.MetricsIntervalSec <= 0).
const DefaultIntervalSec = 15

// Reporter drives periodic sampling + upload. Run() must be started once
// with the agent's root context; UpdateInterval() hot-applies a new interval
// pushed by the server via config_update without restarting the loop.
type Reporter struct {
	monitor  *resource.Monitor
	client   *comm.Client
	interval time.Duration
	// Buffered 1: UpdateInterval never blocks the config_update handler;
	// an already-pending update just replaces the value.
	intervalCh chan time.Duration
	closeCh    chan struct{}
}

// NewReporter builds a reporter. intervalSec <= 0 falls back to
// DefaultIntervalSec (15s).
func NewReporter(m *resource.Monitor, c *comm.Client, intervalSec int) *Reporter {
	if intervalSec <= 0 {
		intervalSec = DefaultIntervalSec
	}
	return &Reporter{
		monitor:    m,
		client:     c,
		interval:   time.Duration(intervalSec) * time.Second,
		intervalCh: make(chan time.Duration, 1),
		closeCh:    make(chan struct{}),
	}
}

// Run starts the sampling loop in a background goroutine. It stops when ctx
// is cancelled (agent shutdown) or Stop() is called. Safe to call once.
func (r *Reporter) Run(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.closeCh:
				return
			case d := <-r.intervalCh:
				if d > 0 {
					r.interval = d
					ticker.Reset(d)
				}
			case <-ticker.C:
				r.client.SendMetrics(r.monitor.Sample())
			}
		}
	}()
}

// Stop terminates the loop. Idempotent; also covered by ctx cancellation.
func (r *Reporter) Stop() {
	select {
	case <-r.closeCh:
		// already closed
	default:
		close(r.closeCh)
	}
}

// UpdateInterval hot-applies a new interval (seconds) from config_update.
// Values <= 0 are ignored; a pending update in the channel is replaced.
func (r *Reporter) UpdateInterval(sec int) {
	if sec <= 0 {
		return
	}
	select {
	case r.intervalCh <- time.Duration(sec) * time.Second:
	default:
		// Channel full: drain the stale value and push the new one so a
		// burst of config_updates converges to the latest interval.
		select {
		case <-r.intervalCh:
		default:
		}
		r.intervalCh <- time.Duration(sec) * time.Second
	}
}
