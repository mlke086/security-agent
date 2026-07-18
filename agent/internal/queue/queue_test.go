package queue

import (
	"path/filepath"
	"testing"
)

func TestPushPopAllOrderAndClear(t *testing.T) {
	q, err := Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()

	if err := q.Push("scan_result", map[string]string{"a": "1"}); err != nil {
		t.Fatalf("Push 1: %v", err)
	}
	if err := q.Push("scan_step", map[string]string{"b": "2"}); err != nil {
		t.Fatalf("Push 2: %v", err)
	}
	if c, _ := q.Count(); c != 2 {
		t.Errorf("Count = %d, want 2", c)
	}

	items, err := q.PopAll()
	if err != nil {
		t.Fatalf("PopAll: %v", err)
	}
	if len(items) != 2 || items[0].Type != "scan_result" || items[1].Type != "scan_step" {
		t.Errorf("PopAll order/content wrong: %+v", items)
	}
	if c, _ := q.Count(); c != 0 {
		t.Errorf("Count after PopAll = %d, want 0", c)
	}

	empty, _ := q.PopAll()
	if len(empty) != 0 {
		t.Errorf("empty PopAll = %d, want 0", len(empty))
	}
}
