//go:build windows

package windowsupdateexecutor

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// VerifyServiceContext proves only this dedicated entry's LocalSystem session-zero
// primary process token. It never relaxes VerifyForegroundContext.
func VerifyServiceContext() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOARCH != "amd64" {
		return ErrToken
	}
	v := windows.RtlGetVersion()
	if v == nil || v.ProductType == 2 {
		return ErrToken
	}
	if e := verifyNativeToken(); e != nil {
		return e
	}
	var t windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t) != nil {
		return ErrToken
	}
	defer t.Close()
	u, e := t.GetTokenUser()
	if e != nil || u.User.Sid == nil || u.User.Sid.String() != "S-1-5-18" {
		return ErrToken
	}
	var session, n uint32
	if windows.GetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &n) != nil || n != 4 || session != 0 {
		return ErrToken
	}
	return nil
}
