package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/queue"
	"github.com/security-agent/agent/internal/scan"
)

// debugEnabled reports whether verbose message-logging is on. P3-1 修复：
// 调试日志会记录敏感 payload（scan 目标/签名串），默认关闭，仅 AGENT_DEBUG=1 时开启。
var debugEnabled = os.Getenv("AGENT_DEBUG") == "1"

// dbgLog 仅在 AGENT_DEBUG=1 时打印，避免生产环境把敏感 payload 落 journalctl。
func dbgLog(format string, args ...any) {
	if debugEnabled {
		log.Printf(format, args...)
	}
}

// Client manages the WebSocket connection to the server.
type Client struct {
	cfg         *config.Config
	ruleVersion atomic.Value // string; updated by HandleRuleUpdate, read by heartbeat
	Queue       *queue.Queue
	conn        *websocket.Conn
	mu          sync.Mutex

	// StatusReason holds the most recent self-protection pause reason.
	// The heartbeat loop reads it on every tick and embeds it in the
	// payload so the console can show *why* the host is paused.
	statusReason atomic.Value // string, empty == online

	done chan struct{}

	// Message handlers
	OnScanCommand  func(payload json.RawMessage)
	OnRuleUpdate   func(payload json.RawMessage)
	OnAgentUpgrade func(payload json.RawMessage)
	OnConfigUpdate func(payload json.RawMessage)
	// P1-GO-06 (2026-07-19): scan_cancel dispatcher. Wired to engine.CancelScan.
	OnScanCancel   func(payload json.RawMessage)
}

// NewClient creates a new WebSocket client.
func NewClient(cfg *config.Config) (*Client, error) {
	c := &Client{
		cfg:  cfg,
		done: make(chan struct{}),
	}
	c.ruleVersion.Store(cfg.RuleVersion)
	return c, nil
}

// SetRuleVersion records the rule-pack version the agent last loaded. Safe to
// call from any goroutine; the next heartbeat tick reports it so the server
// stops re-pushing the same pack. Called by updater.HandleRuleUpdate.
func (c *Client) SetRuleVersion(v string) {
	c.ruleVersion.Store(v)
}

// RuleVersion returns the current rule-pack version (thread-safe).
func (c *Client) RuleVersion() string {
	if v := c.ruleVersion.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// SetStatusReason records a self-protection reason (e.g. "paused:cpu_high")
// or an empty string when the host is healthy. Safe to call from any
// goroutine; the next heartbeat tick picks it up.
func (c *Client) SetStatusReason(reason string) {
	c.statusReason.Store(reason)
}

// Connect establishes the WebSocket connection and starts heartbeat + read loop.
func (c *Client) Connect(ctx context.Context) error {
	// P1-GO-4: pass agent_id in the query (it is how the gateway binds a
	// connection to a host row) but keep the auth token out of the URL --
	// URL tokens show up in process listings, reverse-proxy logs, and any
	// shallow HTTP capture by an intermediate node. Use the standard
	// Authorization: Bearer header instead.
	wsURL := fmt.Sprintf("%s/api/v1/agents/ws?agent_id=%s",
		c.cfg.ConsoleURL, c.cfg.AgentID)

	// Replace https:// with wss://
	if parsed, err := url.Parse(wsURL); err == nil {
		if parsed.Scheme == "https" {
			parsed.Scheme = "wss"
		} else {
			parsed.Scheme = "ws"
		}
		wsURL = parsed.String()
	}

	// Header carrying the bearer token. Built once per dial; the gorilla
	// websocket Dialer passes it through as part of the HTTP upgrade
	// request, never as part of the URL.
	headers := http.Header{}
	if c.cfg.AgentToken != "" {
		headers.Set("Authorization", "Bearer "+c.cfg.AgentToken)
	}

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
	reconnect:
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		dialer := &websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		if c.cfg.CAPath != "" {
			caCert, err := os.ReadFile(c.cfg.CAPath)
			if err == nil {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				dialer.TLSClientConfig = &tls.Config{RootCAs: caCertPool}
			}
		}

		dialer.HandshakeTimeout = 10 * time.Second

		conn, _, err := dialer.DialContext(ctx, wsURL, headers)
		if err != nil {
			log.Printf("[comm] dial failed: %v (retry in %v)", err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
		}

		c.mu.Lock()
		c.conn = conn
		c.mu.Unlock()
		backoff = 1 * time.Second

		log.Println("[comm] connected to server")

		// F3-SELINUX (2026-07-23): when the context is cancelled (e.g. SIGTERM
		// from systemd during an upgrade), immediately close the WebSocket so
		// the read loop unblocks instead of waiting for the 90s read deadline.
		// Without this the read loop holds the process alive and systemd escalates
		// to SIGKILL after TimeoutStopSec.
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()

		// Process offline queue
		go c.processQueue()

		// Start heartbeat
		go c.heartbeatLoop(ctx)

		// Read loop. P1-GO-03: bound each ReadMessage with a deadline so a
		// wedged TCP read cannot pin the agent. 后端每 30s 发 keepalive 保活，
		// 故 deadline 设 90s（3 个 keepalive 周期）-- 后端正常时每 30s 重置
		// deadline；后端宕机时 90s 后到期重连。既不丢命令（keepalive 持续
		// 重置 deadline，rule_update/scan_command 随时能送达），又能检测死连接。
		readDeadline := 90 * time.Second
		for {
			if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
				log.Printf("[comm] set_read_deadline_failed: %v", err)
			}
			_, raw, err := conn.ReadMessage()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// F-WSL (2026-07-21): the previous `continue` here
					// re-entered ReadMessage on the SAME failed connection,
				// which panics inside gorilla/websocket with
				// "repeated read on failed websocket connection".
					// Instead, close the socket and break so the outer
				// reconnect loop takes over with backoff.
					log.Printf("[comm] read deadline reached, closing and reconnecting")
					_ = conn.Close()
					goto reconnect
				}
				log.Printf("[comm] read error: %v", err)
				break
			}
			// P1-GO-03: run handleMessage on its own goroutine so a slow
			// upgrade download (which can take 10-30s on a slow link) does
			// not block the read loop and starve heartbeats.
			go c.handleMessage(raw)
		}

		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
		close(c.done)
		c.done = make(chan struct{})
		log.Println("[comm] disconnected, reconnecting...")
	}
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(c.cfg.HeartbeatSec) * time.Second)
	defer ticker.Stop()
	// 连上后立即发首个心跳，让服务端尽快比对规则版本下发 rule_update，
	// 不必等首个 ticker（60s）-- 加速首次规则分发。
	immediate := make(chan struct{}, 1)
	immediate <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-immediate:
		case <-ticker.C:
		}
		reason := ""
		if v := c.statusReason.Load(); v != nil {
			if s, ok := v.(string); ok {
				reason = s
			}
		}
		msg := map[string]interface{}{
			"v":    1,
			"type": "heartbeat",
			"ts":   time.Now().UTC().Format(time.RFC3339),
			"payload": map[string]interface{}{
				"agent_version": c.cfg.AgentVersion,
				"rule_version":  c.RuleVersion(),
				"hostname":      getHostname(),
				"os":            runtime.GOOS,
				"cpu":           0,
				"mem":           0,
				"status_reason": reason,
			},
		}
		c.send(msg)
	}
}

func (c *Client) handleMessage(raw []byte) {
	var msg struct {
		V       int             `json:"v"`
		Type    string          `json:"type"`
		TS      string          `json:"ts"`
		Sig     string          `json:"sig"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		log.Printf("[comm] failed to parse message: %v", err)
		return
	}

	switch msg.Type {
	case "scan_command":
		// P3-1 修复：调试日志改用 dbgLog（AGENT_DEBUG=1 才输出），并去掉
		// 原先重复打印两遍的残留。
		dbgLog("[comm] dbg_scan_cmd type=%q ts=%q payload=%s sig=%q",
			msg.Type, msg.TS, string(msg.Payload), msg.Sig)
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnScanCommand != nil {
			c.OnScanCommand(msg.Payload)
		}
	case "rule_update":
		// P1-GO-2: rule_update is in crypto.SensitiveTypes and must be signed.
		// Without verification a MitM on the (default plain ws://) channel could
		// inject arbitrary rule packs or trigger SSRF against the agent.
		dbgLog("[comm] dbg_msg type=%q ts=%q payload=%s sig=%q",
			msg.Type, msg.TS, string(msg.Payload), msg.Sig)
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnRuleUpdate != nil {
			c.OnRuleUpdate(msg.Payload)
		}
	case "agent_upgrade":
		dbgLog("[comm] dbg_msg type=%q ts=%q payload=%s sig=%q",
			msg.Type, msg.TS, string(msg.Payload), msg.Sig)
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnAgentUpgrade != nil {
			c.OnAgentUpgrade(msg.Payload)
		}
	case "config_update":
		dbgLog("[comm] dbg_msg type=%q ts=%q payload=%s sig=%q",
			msg.Type, msg.TS, string(msg.Payload), msg.Sig)
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnConfigUpdate != nil {
			c.OnConfigUpdate(msg.Payload)
		}
	case "scan_cancel":
		dbgLog("[comm] dbg_msg type=%q ts=%q payload=%s sig=%q",
			msg.Type, msg.TS, string(msg.Payload), msg.Sig)
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		log.Println("[comm] received scan_cancel")
		if c.OnScanCancel != nil {
			c.OnScanCancel(msg.Payload)
		} else {
			log.Println("[comm] scan_cancel ignored (no handler wired)")
		}
	case "keepalive":
		// 后端每 30s 发的应用层保活，重置 read deadline，无需处理。
	default:
		// 其他未知类型静默忽略，避免日志噪音
		log.Printf("[comm] unknown message type: %s", msg.Type)
	}
}

func (c *Client) send(msg map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	connNil := c.conn == nil
	msgType, _ := msg["type"].(string)
	log.Printf("[comm] c.send type=%q connNil=%v", msgType, connNil)
	if connNil {
		// Push to offline queue
		if c.Queue != nil {
			c.Queue.Push("outgoing", msg)
		}
		return
	}
	// P1-GO-02 (2026-07-19): bound the WriteJSON call with a deadline so a
	// stuck TCP write (e.g. server accepted the connection but the read
	// side is wedged) cannot pin the whole agent forever. 10s is well above
	// any legitimate heartbeat / scan_result write on a healthy network and
	// well below the systemd RestartSec=10 budget, so a stuck socket is
	// detected + the connection torn down in time for reconnect.
	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[comm] set_write_deadline_failed: %v", err)
	}
	err := c.conn.WriteJSON(msg)
	if err != nil {
		log.Printf("[comm] send error: %v", err)
	} else {
		log.Printf("[comm] send OK type=%q", msgType)
	}
	// Clear the deadline so subsequent reads / heartbeats are not bound
	// by this 10s budget.
	_ = c.conn.SetWriteDeadline(time.Time{})
}

// SendStep sends a scan_step progress update to the server.
func (c *Client) SendStep(taskID, step, status, message string) {
	c.send(map[string]interface{}{
		"v":    1,
		"type": "scan_step",
		"ts":   time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]string{
			"task_id": taskID,
			"step":    step,
			"status":  status,
			"message": message,
		},
	})
}

// SendResult sends scan findings to the server.
func (c *Client) SendResult(taskID, hostname string, findings interface{}, batch int, isFinal bool) {
	log.Printf("[comm] SendResult task=%s batch=%d is_final=%v findings=%d",
		taskID, batch, isFinal, len(findingsAsSlice(findings)))
	c.send(map[string]interface{}{
		"v":    1,
		"type": "scan_result",
		"ts":   time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]interface{}{
			"task_id":  taskID,
			"hostname": hostname,
			"findings": findings,
			"batch":    batch,
			"is_final": isFinal,
		},
	})
}

// findingsAsSlice is a small helper for the debug log above. We can't
// use len() directly on an interface{} because the runtime won't count
// the elements of a typed slice hidden behind the interface.
func findingsAsSlice(f interface{}) []scan.Finding {
	if s, ok := f.([]scan.Finding); ok {
		return s
	}
	return nil
}

// SendTaskAck acknowledges a scan command.
func (c *Client) SendTaskAck(taskID string, accepted bool, reason string) {
	c.send(map[string]interface{}{
		"v":    1,
		"type": "task_ack",
		"ts":   time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]interface{}{
			"task_id":  taskID,
			"accepted": accepted,
			"reason":   reason,
		},
	})
}

// SendUpdateAck acknowledges a rule_update, agent_upgrade, or config_update.
func (c *Client) SendUpdateAck(kind, version string, ok bool, errMsg string) {
	c.send(map[string]interface{}{
		"v":    1,
		"type": "update_ack",
		"ts":   time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]interface{}{
			"kind":    kind,
			"version": version,
			"ok":      ok,
			"error":   errMsg,
		},
	})
}

// processQueue sends all queued messages after reconnection.
func (c *Client) processQueue() {
	if c.Queue == nil {
		return
	}
	items, err := c.Queue.PopAll()
	if err != nil || len(items) == 0 {
		return
	}
	log.Printf("[comm] replaying %d queued messages", len(items))
	for _, item := range items {
		var msg map[string]interface{}
		if err := json.Unmarshal(item.Payload, &msg); err != nil {
			continue
		}
		c.send(msg)
	}
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getCPUUsage() int {
	return runtime.NumGoroutine()
}

func getMemUsage() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int(m.Alloc / 1024 / 1024)
}
