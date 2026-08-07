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

// killMinProtectedPID / killMaxPID bound the attackable range. PIDs below
// 10 are kernel/init/systemd critical processes; the documented wire
// contract is 1..4194304 but nothing enforced the upper bound (V13 P2-18).
const (
	killMinProtectedPID = 10 // PIDs 1..10 are never killable
	killMaxPID          = 4194304
)

// KillProcess sends a POSIX signal to ``params.pid``.
//
// Wire format (matches src/agents/response_actions.py KillProcessPayload):
//   {"pid": <int 1..4194304>, "signal": "SIGKILL" | "SIGTERM" | "SIGABRT"}
//
// Safety:
//   - Refuses to target the Agent's own PID (os.Getpid).
//   - Refuses PID 0, negatives, the kernel/system range 1..10 (init,
//     systemd, kthreadd) and anything above 4194304 (defence-in-depth;
//     the server should already reject these but we do not trust it).
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
	if p.Pid <= killMinProtectedPID {
		return Result{Ok: false, Detail: fmt.Sprintf(
			"pid %d is in the protected kernel/system range 1-%d", p.Pid, killMinProtectedPID)}
	}
	if p.Pid > killMaxPID {
		return Result{Ok: false, Detail: fmt.Sprintf("pid %d exceeds max %d", p.Pid, killMaxPID)}
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
