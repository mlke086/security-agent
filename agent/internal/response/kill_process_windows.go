//go:build windows

package response

import (
	"fmt"
	"os/exec"
)

// sendSignalPlatform is the Windows implementation. Uses taskkill because
// syscall.Kill in the Go stdlib only works for the current process on
// Windows (it shells out to TerminateProcess(self)).
func sendSignalPlatform(pid int, sig string) error {
	flag := sigToTaskkillFlag(sig)
	cmd := exec.Command("taskkill", flag, "/PID", pidArg(pid))
	out, err := cmd.CombinedOutput()
	logKill(pid, sig, err)
	if err == nil {
		return nil
	}
	// taskkill exits 128 with "process not found" or "access denied"
	// messages in stdout/stderr. Map the two common cases to the
	// shared sentinels so the server can render them consistently.
	msg := string(out)
	if contains(msg, "not found") {
		return fmt.Errorf("%w: %s", ErrProcessNotFound, trim(msg))
	}
	if contains(msg, "Access is denied") {
		return fmt.Errorf("%w: %s", ErrPermissionDenied, trim(msg))
	}
	return fmt.Errorf("taskkill failed: %s", trim(msg))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
