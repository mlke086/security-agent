package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/queue"
)

// Client manages the WebSocket connection to the server.
type Client struct {
	cfg         *config.Config
	ruleVersion string
	Queue   *queue.Queue
	conn    *websocket.Conn
	mu     sync.Mutex
	done   chan struct{}

	// Message handlers
	OnScanCommand  func(payload json.RawMessage)
	OnRuleUpdate   func(payload json.RawMessage)
	OnAgentUpgrade func(payload json.RawMessage)
	OnConfigUpdate func(payload json.RawMessage)
}

// NewClient creates a new WebSocket client.
func NewClient(cfg *config.Config) (*Client, error) {
	return &Client{
		cfg:  cfg,
		done: make(chan struct{}),
	}, nil
}

// Connect establishes the WebSocket connection and starts heartbeat + read loop.
func (c *Client) Connect(ctx context.Context) error {
	wsURL := fmt.Sprintf("%s/api/v1/agents/ws?agent_id=%s&token=%s",
		c.cfg.ConsoleURL, c.cfg.AgentID, c.cfg.AgentToken)

	// Replace https:// with wss://
	if parsed, err := url.Parse(wsURL); err == nil {
		if parsed.Scheme == "https" {
			parsed.Scheme = "wss"
		} else {
			parsed.Scheme = "ws"
		}
		wsURL = parsed.String()
	}

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
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

		conn, _, err := dialer.DialContext(ctx, wsURL, nil)
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

		// Process offline queue
		go c.processQueue()

		// Start heartbeat
		go c.heartbeatLoop(ctx)

		// Read loop
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[comm] read error: %v", err)
				break
			}
			c.handleMessage(raw)
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			msg := map[string]interface{}{
				"v":   1,
				"type": "heartbeat",
				"ts":  time.Now().UTC().Format(time.RFC3339),
				"payload": map[string]interface{}{
					"agent_version": "0.1.0",
					"rule_version":  c.ruleVersion,
					"hostname":      getHostname(),
					"os":            runtime.GOOS,
					"cpu":           0,
					"mem":           0,
				},
			}
			c.send(msg)
		}
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
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnRuleUpdate != nil {
			c.OnRuleUpdate(msg.Payload)
		}
	case "agent_upgrade":
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnAgentUpgrade != nil {
			c.OnAgentUpgrade(msg.Payload)
		}
	case "config_update":
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		if c.OnConfigUpdate != nil {
			c.OnConfigUpdate(msg.Payload)
		}
	case "scan_cancel":
		if err := crypto.Verify(msg.Type, msg.TS, msg.Payload, msg.Sig); err != nil {
			log.Printf("[comm] signature verification failed for %s: %v", msg.Type, err)
			return
		}
		log.Println("[comm] received scan_cancel")
	default:
		log.Printf("[comm] unknown message type: %s", msg.Type)
	}
}

func (c *Client) send(msg map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		// Push to offline queue
		if c.Queue != nil {
			c.Queue.Push("outgoing", msg)
		}
		return
	}
	if err := c.conn.WriteJSON(msg); err != nil {
		log.Printf("[comm] send error: %v", err)
	}
}

// SendStep sends a scan_step progress update to the server.
func (c *Client) SendStep(taskID, step, status, message string) {
	c.send(map[string]interface{}{
		"v":   1,
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
	c.send(map[string]interface{}{
		"v":   1,
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

// SendTaskAck acknowledges a scan command.
func (c *Client) SendTaskAck(taskID string, accepted bool, reason string) {
	c.send(map[string]interface{}{
		"v":   1,
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
		"v":   1,
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
