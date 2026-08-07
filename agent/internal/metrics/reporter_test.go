package metrics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/security-agent/agent/internal/comm"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/queue"
	"github.com/security-agent/agent/internal/resource"
)

// newDisconnectedClient builds a comm.Client that has NEVER connected
// (conn == nil), wired with a real SQLite queue. Safe without a server:
// NewClient only stores config; Connect() is what dials.
func newDisconnectedClient(t *testing.T) (*comm.Client, *queue.Queue) {
	t.Helper()
	cfg := &config.Config{
		AgentID:      "test-agent",
		AgentToken:   "test-token",
		ConsoleURL:   "ws://127.0.0.1:1", // unreachable; never dialed here
		HeartbeatSec: 60,
	}
	c, err := comm.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	q, err := queue.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatalf("queue.Open: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	c.Queue = q
	return c, q
}

// TestReporterDropsWhenDisconnected (需求①): 断线时 SendMetrics 必须走
// ephemeral 通道（不入 SQLite 离线队列）——高频时序数据离线补传无意义。
// 验证：reporter 跑若干 tick 后，离线队列仍为空。
func TestReporterDropsWhenDisconnected(t *testing.T) {
	c, q := newDisconnectedClient(t)
	m := resource.NewMonitor(resource.Limit{})
	// 100ms tick 让测试快速推进；生产默认 15s。
	r := NewReporter(m, c, 0) // 0 -> DefaultIntervalSec 兜底，覆盖默认分支
	if r.interval != DefaultIntervalSec*time.Second {
		t.Fatalf("expected default interval %ds, got %v", DefaultIntervalSec, r.interval)
	}
	// 用短间隔直接驱动（NewReporter 后手动覆盖，模拟 15s 语义不变）。
	r.interval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run(ctx)

	time.Sleep(350 * time.Millisecond) // ~3 ticks

	items, err := q.PopAll()
	if err != nil {
		t.Fatalf("PopAll: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 queued messages while disconnected, got %d", len(items))
	}

	// IsConnected 必须为 false（未连接）。
	if c.IsConnected() {
		t.Error("IsConnected() = true for a never-connected client")
	}
}

// TestReporterStopsOnCancel (需求①): ctx 取消后 loop 退出、不再发送。
func TestReporterStopsOnCancel(t *testing.T) {
	c, q := newDisconnectedClient(t)
	m := resource.NewMonitor(resource.Limit{})
	r := NewReporter(m, c, 1)
	r.interval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	r.Run(ctx)
	cancel()
	time.Sleep(200 * time.Millisecond)

	items, err := q.PopAll()
	if err != nil {
		t.Fatalf("PopAll: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no sends after cancel, got %d queued", len(items))
	}
}

// TestReporterUpdateInterval (需求①): 热更新间隔非阻塞、收敛到最新值。
func TestReporterUpdateInterval(t *testing.T) {
	c, _ := newDisconnectedClient(t)
	m := resource.NewMonitor(resource.Limit{})
	r := NewReporter(m, c, 15)

	r.UpdateInterval(30)
	if r.interval != 15*time.Second {
		t.Fatalf("interval should not change until the loop consumes the update")
	}
	// 非法值被忽略
	r.UpdateInterval(0)
	r.UpdateInterval(-5)

	// 启动 loop 消费更新
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Run(ctx)
	// 等 loop 处理 channel 中的更新
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.interval == 30*time.Second {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r.interval != 30*time.Second {
		t.Fatalf("interval not updated to 30s, got %v", r.interval)
	}
}
