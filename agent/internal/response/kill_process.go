package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// KillProcess sends a POSIX signal to ``params.pid``.
//
// Wire format (matches src/agents/response_actions.py KillProcessPayload):
//   {"pid": <int 1..4194304>, "signal": "SIGKILL" | "SIGTERM" | "SIGABRT"}
//
// Safety:
//   - Refuses to target the Agent's own PID (os.Getpid).
//   - Refuses PID 0 and negatives (defence-in-depth; the server should
//     already reject these but we do not trust it).
//   - On Windows, falls back to ``taskkill /F /PID <pid>`` because the
//     syscall package's ``Process.Kill`` only works on the current PID on
//     Windows. taskkill ships with every desktop/server SKU we target.
func KillProcess(params json.RawMessage) Result {
	var p struct {
		Pid    int    `json:"pid"`
		Signal string `json:"signal"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return Result{Ok: false, Detail: "invalid params: " + err.Error()}
	}
	if p.Pid <= 0 {
		return Result{Ok: false, Detail: fmt.Sprintf("pid must be > 0, got %d", p.Pid)}
	}
	if p.Pid == os.Getpid() {
		return Result{Ok: false, Detail: "refusing to target agent's own pid"}
	}

	sig := strings.ToUpper(strings.TrimSpace(p.Signal))
	if sig == "" {
		sig = "SIGKILL"
	}
	switch sig {
	case "SIGKILL", "SIGTERM", "SIGABRT":
		// supported
	default:
		return Result{Ok: false, Detail: "unsupported signal: " + p.Signal}
	}

	if err := sendSignal(p.Pid, sig); err != nil {
		return Result{Ok: false, Detail: err.Error()}
	}
	return Result{Ok: true, Detail: fmt.Sprintf("sent %s to pid %d", sig, p.Pid)}
}

// sendSignal is the platform-portable entry point. The Windows build
// shells out to taskkill; the POSIX build uses syscall.Kill.
func sendSignal(pid int, sig string) error {
	return sendSignalPlatform(pid, sig)
}

// pidArg formats a PID for the current platform's command line tools.
func pidArg(pid int) string { return strconv.Itoa(pid) }

// sigToTaskkillFlag maps our canonical signal name to the matching
// taskkill /F flag value. taskkill uses /F for SIGKILL-equivalent; the
// other signals do not have a clean equivalent so we map them all to
// graceful termination via /F (operators usually want the process gone).
//
// Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill
func sigToTaskkillFlag(sig string) string {
	// /F always force-terminates; we ignore SIGTERM/SIGABRT semantics on
	// Windows because the agent rarely runs there in production.
	_ = sig
	return "/F"
}

// --- shared error helpers used by both platforms --------------------------

var (
	ErrProcessNotFound = errors.New("process not found")
	ErrPermissionDenied = errors.New("permission denied")
)

// logKill returns the canonical "we tried to kill PID X" log line so the
// agent journal has a paper trail even when the action itself succeeds.
func logKill(pid int, sig string, err error) {
	if err != nil {
		log.Printf("[response] kill_process pid=%d sig=%s err=%v", pid, sig, err)
	} else {
		log.Printf("[response] kill_process pid=%d sig=%s ok", pid, sig)
	}
}
