//go:build windows

package windowsupdateexecutor

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// VerifyForegroundContext is a bounded read-only own-token check. It never
// elevates, enables privileges, enumerates processes, or opens a foreign token.
// The explicit foreground entry requires an interactive nonzero session.
func VerifyForegroundContext() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e := verifyNativeToken(); e != nil {
		return e
	}
	var t windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t) != nil {
		return ErrToken
	}
	defer t.Close()
	var session, n uint32
	if windows.GetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &n) != nil || n != 4 || session == 0 {
		return ErrUnavailable
	}
	raw := make([]byte, maxTokenBytes)
	if windows.GetTokenInformation(t, windows.TokenGroups, &raw[0], uint32(len(raw)), &n) != nil || n == 0 || n > uint32(len(raw)) {
		return ErrToken
	}
	valid := foregroundGroups(raw[:n], uint64(uintptr(unsafe.Pointer(&raw[0]))), int(unsafe.Sizeof(uintptr(0))))
	runtime.KeepAlive(raw)
	if !valid {
		return ErrUnavailable
	}
	return nil
}
