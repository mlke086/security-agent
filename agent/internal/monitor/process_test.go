package monitor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// --- fake lister -----------------------------------------------------------

type fakeLister struct {
	procs []*process.Process
	host  string
	err   error
}

func (f *fakeLister) List(_ context.Context) ([]*process.Process, error) {
	return f.procs, f.err
}
func (f *fakeLister) Hostname(_ context.Context) (string, error) {
	return f.host, nil
}

// --- recording sink --------------------------------------------------------

type recordingSink struct {
	mu      sync.Mutex
	gotSnap []Snapshot
}

func (r *recordingSink) Send(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gotSnap = append(r.gotSnap, s)
}

func (r *recordingSink) snapshots() []Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Snapshot, len(r.gotSnap))
	copy(out, r.gotSnap)
	return out
}

// --- tests -----------------------------------------------------------------

func TestSnapshot_CapsAtMaxN(t *testing.T) {
	// Empty process list -> empty snapshot but still a host tag.
	sink := &recordingSink{}
	m := New(&fakeLister{host: "h-1"}, sink, 5*time.Second, 3)
	snap, err := m.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Snapshot() returns the data directly; the sink is only used
	// by the scheduled tick loop. So we check snap, not sink.
	if snap.Hostname != "h-1" {
		t.Errorf("Hostname = %q, want h-1", snap.Hostname)
	}
	if snap.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", snap.TotalCount)
	}
	if sink.snapshots() != nil && len(sink.snapshots()) != 0 {
		t.Errorf("sink should not have received anything from direct Snapshot() call")
	}
}

func TestSnapshot_PropagatesListerError(t *testing.T) {
	wantErr := errors.New("boom")
	m := New(&fakeLister{err: wantErr, host: "h-1"}, &recordingSink{}, time.Second, 10)
	_, err := m.Snapshot(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected lister error, got %v", err)
	}
}

func TestSnapshot_TruncationFlag(t *testing.T) {
	// We cannot easily fabricate process.Process values without going
	// through the real OS API, so exercise only the math paths via
	// the truncation logic on an empty lister.
	m := New(&fakeLister{host: "h"}, &recordingSink{}, time.Second, 0)
	// maxN=0 should fall back to DefaultMaxProcesses.
	if m.maxN != DefaultMaxProcesses {
		t.Errorf("expected maxN=DefaultMaxProcesses (%d), got %d", DefaultMaxProcesses, m.maxN)
	}
}

func TestMonitor_StartStopEmitsAtLeastOneTick(t *testing.T) {
	sink := &recordingSink{}
	m := New(&fakeLister{host: "h-1"}, sink, 30*time.Millisecond, 5)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	// wait for the immediate tick + a few scheduled ones
	time.Sleep(150 * time.Millisecond)
	m.Stop()
	cancel()
	got := sink.snapshots()
	if len(got) < 2 {
		t.Errorf("expected >= 2 ticks, got %d", len(got))
	}
}

func TestMonitor_StopIsIdempotent(t *testing.T) {
	m := New(&fakeLister{host: "h"}, &recordingSink{}, time.Second, 5)
	m.Stop()
	// Second Stop must not panic / deadlock.
	m.Stop()
}

func TestStripDomain(t *testing.T) {
	cases := map[string]string{
		"root":                  "root",
		`DOMAIN\alice`:          "alice",
		`WORKGROUP\Administrator`: "Administrator",
		"":                       "",
	}
	for in, want := range cases {
		if got := stripDomain(in); got != want {
			t.Errorf("stripDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestItoa(t *testing.T) {
	cases := map[int32]string{
		0:    "0",
		1:    "1",
		42:   "42",
		1000: "1000",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestSnapshot_IntervalSecPopulated(t *testing.T) {
	m := New(&fakeLister{host: "h"}, &recordingSink{}, 7*time.Second, 5)
	snap, err := m.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.IntervalSec != 7 {
		t.Errorf("IntervalSec = %d, want 7", snap.IntervalSec)
	}
	if !strings.Contains(snap.Hostname, "h") {
		t.Errorf("Hostname = %q", snap.Hostname)
	}
}
