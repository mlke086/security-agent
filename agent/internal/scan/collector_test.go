package scan

import "testing"

func TestCollectorSysVuln(t *testing.T) {
	c := NewCollector()
	items, err := c.CollectSysVuln()
	if err != nil {
		t.Skipf("skipping (no package manager): %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least some packages or kernel info")
	}
	// Verify all items have required fields
	for _, item := range items {
		if item.Type != "package" && item.Type != "kernel" {
			t.Errorf("unexpected item type: %s", item.Type)
		}
		if item.Data["name"] == "" && item.Type == "package" {
			t.Error("package item missing name")
		}
	}
}

func TestCollectorBaseline(t *testing.T) {
	c := NewCollector()
	items, err := c.CollectBaseline()
	if err != nil {
		t.Fatalf("CollectBaseline: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least some baseline items")
	}
	for _, item := range items {
		if item.Category != "baseline" {
			t.Errorf("expected baseline category, got %s", item.Category)
		}
	}
}
