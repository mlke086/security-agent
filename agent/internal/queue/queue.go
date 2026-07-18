// Package queue provides an offline message queue backed by SQLite.
//
// When the WebSocket connection drops, scan_result messages are queued locally
// and replayed on reconnection.
package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Item represents a queued outgoing message.
type Item struct {
	ID      int64           `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	Created string          `json:"created"`
}

// Queue is a thread-safe SQLite-backed FIFO message queue.
type Queue struct {
	db   *sql.DB
	mu   sync.Mutex
	path string
}

// DefaultPath returns the OS-specific queue database path.
func DefaultPath() string {
	dir := "/var/lib/secagent"
	if os.Getenv("OS") == "Windows_NT" {
		dir = filepath.Join(os.Getenv("ProgramData"), "secagent", "queue")
	}
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "offline_queue.db")
}

// Open opens (or creates) the queue database at the given path.
func Open(path string) (*Queue, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS outbox (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		payload TEXT NOT NULL,
		created TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create outbox table: %w", err)
	}

	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_outbox_created ON outbox(created)")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create outbox index: %w", err)
	}

	return &Queue{db: db, path: path}, nil
}

// Push adds a message to the queue.
func (q *Queue) Push(msgType string, payload interface{}) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	_, err = q.db.Exec("INSERT INTO outbox (type, payload) VALUES (?, ?)", msgType, string(payloadBytes))
	return err
}

// PopAll retrieves and deletes all pending messages in FIFO order.
func (q *Queue) PopAll() ([]Item, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	tx, err := q.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT id, type, payload, created FROM outbox ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("query outbox: %w", err)
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		var payloadStr string
		if err := rows.Scan(&item.ID, &item.Type, &payloadStr, &item.Created); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		item.Payload = json.RawMessage(payloadStr)
		items = append(items, item)
	}

	if len(items) > 0 {
		_, err = tx.Exec("DELETE FROM outbox")
		if err != nil {
			return nil, fmt.Errorf("delete outbox: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return items, nil
}

// Count returns the number of pending messages.
func (q *Queue) Count() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	var count int
	err := q.db.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&count)
	return count, err
}

// Close closes the queue database.
func (q *Queue) Close() error {
	return q.db.Close()
}
