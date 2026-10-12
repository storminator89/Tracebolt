//go:build windows

package windowsupdateexecutor

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// Read-only proof, never elevation, impersonation or token adjustment. High or
// System process integrity excludes per-user COM registration. Enabled admin
// membership plus an unrestricted elevated primary token proves the prerequisite
// that high integrity alone does NOT prove (e.g. restricted service identities).
func verifyNativeToken() error {
	return verifyToken(tokenAPI{
		openThread: func() (uintptr, error) {
			var t windows.Token
			e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t)
			if e == windows.ERROR_NO_TOKEN {
				e = errNoToken
			}
			return uintptr(t), e
		},
		openProcess: func() (uintptr, error) {
			var t windows.Token
			e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t)
			return uintptr(t), e
		},
		query: func(t uintptr, class uint32, b []byte) (uint32, error) {
			var p *byte
			if len(b) > 0 {
				p = &b[0]
			}
			var n uint32
			e := windows.GetTokenInformation(windows.Token(t), class, p, uint32(len(b)), &n)
			if e == windows.ERROR_INSUFFICIENT_BUFFER {
				e = errBuffer
			}
			return n, e
		},
		close: func(t uintptr) error { return windows.Token(t).Close() },
		base:  func(b []byte) uint64 { return uint64(uintptr(unsafe.Pointer(&b[0]))) },
	}, int(unsafe.Sizeof(uintptr(0))))
}
