//go:build !windows

package windowsstate

import "testing"

func TestNoNonWindowsNativeFallback(t *testing.T) {
	o := optionsFixture()
	o.Create = true
	if _, e := Open(`C:\ProgramData\Tracebolt`, o); e != ErrUnsupported {
		t.Fatal("non-Windows native store fallback")
	}
	if _, e := ReadProtected(`C:\ProgramData\Tracebolt\state.json`, testSID, true, 1024); e != ErrUnsupported {
		t.Fatal("non-Windows protected-file fallback")
	}
	if _, e := ReadProtectedInstaller(`C:\ProgramData\Tracebolt\bootstrap.json`, false, 1024); e != ErrUnsupported {
		t.Fatal("non-Windows installer-file fallback")
	}
}
