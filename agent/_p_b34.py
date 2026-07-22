import pathlib
p = pathlib.Path("agent/internal/scan/engine.go")
text = p.read_text(encoding="utf-8")

# Add a cancel registry: taskID -> cancelFn
old_struct = '''	// Callback for sending task ack
	OnAck func(taskID string, accepted bool, reason string)
}'''
new_struct = '''	// Callback for sending task ack
	OnAck func(taskID string, accepted bool, reason string)

	// P1-GO-06 (2026-07-19): registry of in-flight scan cancel funcs so a
	// scan_cancel command from the server can interrupt a long-running scan.
	// Keyed by task_id. Acquire the cancel mutex before mutating.
	cancels   map[string]context.CancelFunc
	cancelMu  sync.Mutex
}'''
assert old_struct in text, "struct anchor not found"
text = text.replace(old_struct, new_struct)

# Update NewScanEngine to initialize the map
old_new = '''	e := &ScanEngine{
		collector: NewCollector(),
		matcher:   NewMatcher(),
	}'''
new_new = '''	e := &ScanEngine{
		collector: NewCollector(),
		matcher:   NewMatcher(),
		cancels:   make(map[string]context.CancelFunc),
	}'''
assert old_new in text, "NewScanEngine anchor not found"
text = text.replace(new_new, new_new)

# In Execute, build a cancellable context and register the cancel.
old_execute = '''// Execute runs a scan. The dispatcher calls this in a goroutine.
func (e *ScanEngine) Execute(cmd ScanCommand, hostname string) {
	taskID := cmd.TaskID
	log.Printf("[engine] starting scan %s on %s (engine=%q)", taskID, hostname, cmd.Engine)'''
new_execute = '''// Execute runs a scan. The dispatcher calls this in a goroutine.
func (e *ScanEngine) Execute(cmd ScanCommand, hostname string) {
	taskID := cmd.TaskID
	log.Printf("[engine] starting scan %s on %s (engine=%q)", taskID, hostname, cmd.Engine)

	// P1-GO-06 (2026-07-19): wrap the whole scan in a cancellable context so
	// the server can abort it mid-run via a scan_cancel command. The cancel
	// funcs are kept in e.cancels so CancelScan(taskID) can find them.
	scanCtx, cancel := context.WithCancel(context.Background())
	e.cancelMu.Lock()
	if e.cancels == nil {
		e.cancels = make(map[string]context.CancelFunc)
	}
	e.cancels[taskID] = cancel
	e.cancelMu.Unlock()
	defer func() {
		cancel()
		e.cancelMu.Lock()
		delete(e.cancels, taskID)
		e.cancelMu.Unlock()
	}()'''
assert old_execute in text, "Execute anchor not found"
text = text.replace(old_execute, new_execute)

# Add CancelScan method at the end of file (just append)
cancel_method = '''

// CancelScan triggers the cancel func registered for taskID. Safe to call
// from any goroutine. P1-GO-06 -- if the task is unknown (already finished
// or never started) this is a no-op, which is what the server expects when
// it sends a duplicate scan_cancel.
func (e *ScanEngine) CancelScan(taskID string) {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	if cancel, ok := e.cancels[taskID]; ok {
		log.Printf("[engine] cancel requested for task %s", taskID)
		cancel()
	} else {
		log.Printf("[engine] cancel for unknown/already-done task %s", taskID)
	}
}
'''
text = text.rstrip() + cancel_method

p.write_text(text, encoding="utf-8")
print("OK")
