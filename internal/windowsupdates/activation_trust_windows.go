//go:build windows

package windowsupdates

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// verifyNativeActivationTrust must run on the locked calling OS thread before
// COM initialization/activation. Microsoft documents that COM ignores per-user
// registration above Medium process integrity. We require High or System and no
// thread impersonation, without changing either token or any registry state.
// https://learn.microsoft.com/en-us/previous-versions/bb756926(v=msdn.10)
func verifyNativeActivationTrust() error {
	return verifyActivationTrust(activationTrustAPI{
		openThread: func() (uintptr, error) {
			var token windows.Token
			err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
			if err == windows.ERROR_NO_TOKEN {
				err = errActivationNoThreadToken
			}
			return uintptr(token), err
		},
		openProcess: func() (uintptr, error) {
			var token windows.Token
			err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
			return uintptr(token), err
		},
		query: func(token uintptr, b []byte) (uint32, error) {
			var ptr *byte
			if len(b) != 0 {
				ptr = &b[0]
			}
			var needed uint32
			err := windows.GetTokenInformation(windows.Token(token), windows.TokenIntegrityLevel, ptr, uint32(len(b)), &needed)
			if err == windows.ERROR_INSUFFICIENT_BUFFER {
				err = errActivationBufferSize
			}
			return needed, err
		},
		close: func(token uintptr) error { return windows.Token(token).Close() },
		bufferBase: func(b []byte) uint64 {
			return uint64(uintptr(unsafe.Pointer(&b[0])))
		},
	}, int(unsafe.Sizeof(uintptr(0))))
}
