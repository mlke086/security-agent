//go:build !windows

package response

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// sendSignalPlatform is the POSIX implementation. Uses syscall.Kill which
// works for any PID the caller has permission to signal.
func sendSignalPlatform(pid int, sig string) error {
	s, ok := signalNum(sig)
	if !ok {
		return fmt.Errorf("unsupported signal: %s", sig)
	}
	err := syscall.Kill(pid, s)
	logKill(pid, sig, err)
	if err == nil {
		return nil
	}
	// syscall.Kill returns ESRCH for "no such process" and EPERM for
	// "you don't own it". Surface both with friendly strings so the
	// server can show them in the operator UI.
	if errors.Is(err, syscall.ESRCH) {
		return ErrProcessNotFound
	}
	if errors.Is(err, syscall.EPERM) {
		return ErrPermissionDenied
	}
	return err
}

func signalNum(sig string) (syscall.Signal, bool) {
	switch sig {
	case "SIGKILL":
		return syscall.SIGKILL, true
	case "SIGTERM":
		return syscall.SIGTERM, true
	case "SIGABRT":
		return syscall.SIGABRT, true
	}
	return 0, false
}

// Ensure os import is used (some POSIX toolchains strip unused imports).
var _ = os.Getpid
