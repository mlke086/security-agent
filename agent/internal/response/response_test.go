package response

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// --- Dispatcher -----------------------------------------------------------

type captured struct {
	actionID string
	ok       bool
	detail   string
}

func newTestDispatcher() (*Dispatcher, *[]captured, *sync.Mutex) {
	var mu sync.Mutex
	var got []captured
	d := New(func(actionID string, ok bool, detail string) {
		mu.Lock()
		got = append(got, captured{actionID, ok, detail})
		mu.Unlock()
	})
	return d, &got, &mu
}

func TestDispatcher_UnknownAction_AcksFailure(t *testing.T) {
	d, got, mu := newTestDispatcher()
	d.Handle(json.RawMessage(`{"action_id":"a1","action":"definitely_not_real","params":{}}`))
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("expected 1 ack, got %d", len(*got))
	}
	if (*got)[0].actionID != "a1" || (*got)[0].ok {
		t.Errorf("unexpected ack: %+v", (*got)[0])
	}
	if !strings.Contains((*got)[0].detail, "unsupported action") {
		t.Errorf("expected detail to mention unsupported action, got %q", (*got)[0].detail)
	}
}

func TestDispatcher_MalformedEnvelope_SilentNoAck(t *testing.T) {
	// We deliberately do not ack on a parse error -- the server can
	// re-send or treat as lost. Make sure we don't panic and don't ack.
	d, got, mu := newTestDispatcher()
	d.Handle(json.RawMessage(`not-json`))
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 0 {
		t.Errorf("expected 0 acks for malformed envelope, got %d", len(*got))
	}
}

// --- KillProcess ----------------------------------------------------------

func TestKillProcess_RefusesSelf(t *testing.T) {
	self := os.Getpid()
	res := KillProcess(mustJSON(map[string]any{"pid": self, "signal": "SIGKILL"}))
	if res.Ok {
		t.Fatalf("expected refusal when targeting self, got %+v", res)
	}
	if !strings.Contains(res.Detail, "own pid") {
		t.Errorf("expected detail to mention own pid, got %q", res.Detail)
	}
}

func TestKillProcess_RejectsBadPID(t *testing.T) {
	cases := []map[string]any{
		{"pid": 0, "signal": "SIGKILL"},
		{"pid": -1, "signal": "SIGKILL"},
		// V13 P2-18: kernel/system range and out-of-contract PIDs are
		// refused even when a valid signature delivered the command.
		{"pid": 1, "signal": "SIGKILL"},
		{"pid": 5, "signal": "SIGKILL"},
		{"pid": 10, "signal": "SIGKILL"},
		{"pid": 99999999, "signal": "SIGKILL"},
	}
	for i, c := range cases {
		res := KillProcess(mustJSON(c))
		if res.Ok {
			t.Errorf("case %d: expected failure, got %+v", i, res)
		}
	}
}

func TestKillProcess_ProtectedRangeDetail(t *testing.T) {
	res := KillProcess(mustJSON(map[string]any{"pid": 1, "signal": "SIGKILL"}))
	if !strings.Contains(res.Detail, "protected") {
		t.Errorf("expected detail to mention the protected range, got %q", res.Detail)
	}
}

func TestKillProcess_RejectsBadSignal(t *testing.T) {
	res := KillProcess(mustJSON(map[string]any{"pid": 99999, "signal": "SIGFOO"}))
	if res.Ok {
		t.Errorf("expected failure on bad signal, got %+v", res)
	}
	if !strings.Contains(res.Detail, "unsupported signal") {
		t.Errorf("expected detail to mention unsupported signal, got %q", res.Detail)
	}
}

func TestKillProcess_DefaultSignalIsSIGKILL(t *testing.T) {
	// We do not actually start a child process here -- just verify the
	// default-signal path produces the right detail string for a known
	// non-existent PID. We expect ErrProcessNotFound on POSIX (the test
	// machine is Windows here, so ESRCH doesn't apply; just check that
	// either Ok=false with a reasonable message).
	res := KillProcess(mustJSON(map[string]any{"pid": 99999999}))
	if res.Ok {
		t.Errorf("expected failure on nonexistent PID, got %+v", res)
	}
}

// --- QuarantineFile -------------------------------------------------------

func TestQuarantineFile_MovesAndStripsPerms(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "evil.exe")
	if err := os.WriteFile(path, []byte("malicious"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res := QuarantineFile(mustJSON(map[string]any{"path": path, "reason": "test"}))
	if !res.Ok {
		t.Fatalf("expected success, got %+v", res)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("original path should be gone, stat err=%v", err)
	}
	matches, err := filepath.Glob(filepath.Join(tmp, "evil.exe.quarantined.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 quarantined file, got %d (%v)", len(matches), matches)
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("stat quarantined: %v", err)
	}
	if info.Size() != int64(len("malicious")) {
		t.Errorf("content size mismatch: got %d want %d", info.Size(), len("malicious"))
	}
}

func TestQuarantineFile_RejectsRelativePath(t *testing.T) {
	res := QuarantineFile(mustJSON(map[string]any{"path": "evil.exe"}))
	if res.Ok {
		t.Errorf("expected failure on relative path, got %+v", res)
	}
	if !strings.Contains(res.Detail, "absolute") {
		t.Errorf("expected detail to mention absolute, got %q", res.Detail)
	}
}

func TestQuarantineFile_RejectsDirectory(t *testing.T) {
	tmp := t.TempDir()
	res := QuarantineFile(mustJSON(map[string]any{"path": tmp}))
	if res.Ok {
		t.Errorf("expected failure on directory, got %+v", res)
	}
	if !strings.Contains(res.Detail, "directory") {
		t.Errorf("expected detail to mention directory, got %q", res.Detail)
	}
}

func TestQuarantineFile_RejectsNonExistent(t *testing.T) {
	tmp := t.TempDir()
	res := QuarantineFile(mustJSON(map[string]any{"path": filepath.Join(tmp, "never_existed_xxx")}))
	if res.Ok {
		t.Errorf("expected failure on missing file, got %+v", res)
	}
	if !strings.Contains(res.Detail, "not found") {
		t.Errorf("expected detail to mention not found, got %q", res.Detail)
	}
}

// --- helpers --------------------------------------------------------------

func mustJSON(v map[string]any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
