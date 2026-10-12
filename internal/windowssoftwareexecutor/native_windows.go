//go:build windows

package windowssoftwareexecutor

import (
	"context"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspackage"
	job "localrmm/internal/windowssoftwarejob"
)

var msiDLL = windows.NewLazySystemDLL("msi.dll")
var installProduct = msiDLL.NewProc("MsiInstallProductW")
var internalUI = msiDLL.NewProc("MsiSetInternalUI")
var productInfo = msiDLL.NewProc("MsiGetProductInfoExW")

const fixedInstallProperties = `ACTION=INSTALL ALLUSERS=1 MSIINSTALLPERUSER="" REBOOT=ReallySuppress REBOOTPROMPT=S MSIRESTARTMANAGERCONTROL=Disable MSIDISABLERMRESTART=1`

type nativeMSI struct {
	consent job.Consent
	receipt windowspackage.PreparedMSIReceipt
	pin     *windowspackage.PreparedMSI
	used    bool
}

func openNative(ctx context.Context, c job.Consent, r windowspackage.PreparedMSIReceipt) (nativeRuntime, error) {
	if runtime.GOARCH != "amd64" || ctx == nil || ctx.Err() != nil || c.Validate() != nil || !c.Enabled || !c.Acknowledged || !c.PackageReviewAccepted || r.Validate() != nil || r.Package != c.Package {
		return nil, job.ErrAuthority
	}
	if err := verifyNativeToken(); err != nil {
		return nil, err
	}
	return &nativeMSI{consent: c, receipt: r}, nil
}
func (n *nativeMSI) prepare(ctx context.Context, s job.Selection) error {
	if s != n.consent.Package || n.pin != nil {
		return ErrIdentity
	}
	pin, e := windowspackage.OpenPreparedMSI(ctx, n.receipt)
	if e != nil {
		return e
	}
	n.pin = pin
	return nil
}
func (n *nativeMSI) verify(ctx context.Context) error {
	if n.pin == nil || n.receipt.Package != n.consent.Package {
		return ErrIdentity
	}
	return n.pin.Verify(ctx)
}
func (n *nativeMSI) verifyToken() error { return verifyNativeToken() }
func (n *nativeMSI) close() error {
	if n.pin == nil {
		return nil
	}
	return n.pin.Close()
}
func machineProperty(ctx context.Context, s job.Selection, name string) (string, uint32) {
	if ctx == nil || ctx.Err() != nil || !job.ValidSelection(s) {
		return "", 1603
	}
	var buffer [256]uint16
	count := uint32(len(buffer))
	code, _, _ := productInfo.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(s.ProductCode))), 0, 4, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&count))) // MSIINSTALLCONTEXT_MACHINE, no user SID
	if code != 0 || count >= uint32(len(buffer)) {
		return "", uint32(code)
	}
	return windows.UTF16ToString(buffer[:count]), 0
}
func (n *nativeMSI) machineAbsent(ctx context.Context, s job.Selection) job.Fact {
	_, code := machineProperty(ctx, s, "State")
	if code == 1605 {
		return job.Yes
	}
	if code == 0 {
		return job.No
	}
	return job.Unknown
}
func (n *nativeMSI) installerBusy(ctx context.Context) job.Fact {
	if ctx == nil || ctx.Err() != nil {
		return job.Unknown
	}
	// Presence is conservative, never an atomic global installer lock. The OS
	// installer remains final arbiter and a racing1618 consumes this attempt.
	h, e := windows.OpenMutex(windows.SYNCHRONIZE, false, windows.StringToUTF16Ptr(`Global\_MSIExecute`))
	if e == windows.ERROR_FILE_NOT_FOUND {
		return job.No
	}
	if e != nil {
		return job.Unknown
	}
	if windows.CloseHandle(h) != nil {
		return job.Unknown
	}
	return job.Yes
}
func (n *nativeMSI) install(ctx context.Context) (uint32, error) {
	if n.used || n.pin == nil {
		return 0, ErrClosed
	}
	n.used = true
	if ctx == nil || ctx.Err() != nil {
		return 0, job.ErrExpired
	}
	if err := verifyNativeToken(); err != nil {
		return 0, err
	}
	// A dedicated process owns this process-global setting. No shell/msiexec,
	// logging path, transform, patch or caller-controlled property is supplied.
	previous, _, _ := internalUI.Call(2, 0)
	if previous == 0 {
		return 0, ErrSettings
	}
	current, _, _ := internalUI.Call(0, 0)
	if current != 2 {
		return 0, ErrSettings
	}
	path := n.pin.Path()
	if path == "" {
		return 0, ErrIdentity
	}
	// All DLL/procedure resolution is complete before the final current fence.
	if err := installProduct.Find(); err != nil {
		return 0, ErrUnavailable
	}
	if err := job.CheckInstallStart(ctx, time.Now().UTC()); err != nil {
		return 0, err
	}
	code, _, _ := installProduct.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(path))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(fixedInstallProperties))))
	return uint32(code), nil
}
func (n *nativeMSI) registration(ctx context.Context, s job.Selection) job.Fact {
	state, code := machineProperty(ctx, s, "State")
	if code == 1605 {
		return job.No
	}
	if code != 0 {
		return job.Unknown
	}
	if state != "5" {
		return job.No
	}
	version, code := machineProperty(ctx, s, "VersionString")
	if code != 0 {
		return job.Unknown
	}
	packageCode, code := machineProperty(ctx, s, "PackageCode")
	if code != 0 {
		return job.Unknown
	}
	if version != s.Version || packageCode != s.PackageCode {
		return job.No
	}
	return job.Yes
}
