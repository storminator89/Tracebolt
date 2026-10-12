//go:build windows

package windowsupdateipc

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
	"os"
)

// ServiceGuard pins the protected executable through the whole server life.
// It does not establish SCM executor identity: fresh signed nonce proofs do that.
type ServiceGuard struct {
	config     Config
	pins       []windows.Handle
	process    windows.Handle
	descriptor string
}

func OpenServiceGuard(ctx context.Context, c Config, allowQuery bool) (*ServiceGuard, error) {
	if ctx == nil || ctx.Err() != nil || c.Validate() != nil || c.Version != ServiceConfigVersion {
		return nil, ErrPeer
	}
	layout, e := windowsservice.ResolveLayout()
	if e != nil || c.Executable != layout.ProgramFiles+`\Tracebolt\tracebolt-windows-update-service.exe` || c.ObserverReceipt.Layout != layout {
		return nil, ErrPeer
	}
	exe, e := os.Executable()
	if e != nil || exe != c.Executable {
		return nil, ErrPeer
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil || sid != c.ObserverReceipt.ServiceSID {
		return nil, ErrPeer
	}
	snapshot, e := windowsservice.InspectOwned(ctx, c.ObserverReceipt)
	if e != nil || snapshot.State != windowsservice.Running || snapshot.ServiceSID != sid {
		return nil, ErrPeer
	}
	p := &ServiceGuard{config: c}
	p.pins, _, e = holdExecutable(c.Executable)
	fail := func() (*ServiceGuard, error) { p.Close(); return nil, ErrPeer }
	if e != nil {
		return fail()
	}
	hash, e := hashHandle(p.pins[len(p.pins)-1])
	if e != nil || hash != c.ExecutableDigest {
		return fail()
	}
	p.process, e = windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getpid()))
	if e != nil {
		return fail()
	}
	before, e := descriptorText(p.process)
	if e != nil || validateProcessDescriptor(before, sid) != nil {
		return fail()
	}
	found := false
	sd, _ := windows.SecurityDescriptorFromString(before)
	_ = eachACE(sd, func(principal string, mask uint32, k, f byte) error {
		if principal == sid {
			found = true
		}
		return nil
	})
	if !found {
		if !allowQuery || !c.ObserverProcessQueryAcknowledged {
			return fail()
		}
		after, e := windows.SecurityDescriptorFromString(before + fmt.Sprintf("(A;;0x%x;;;%s)", processQueryRights, sid))
		if e != nil {
			return fail()
		}
		// Compare again immediately before changing only this process's DACL.
		current, e := descriptorText(p.process)
		if e != nil || current != before {
			return fail()
		}
		acl, _, e := after.DACL()
		if e != nil || acl == nil {
			return fail()
		}
		control, _, e := after.Control()
		if e != nil {
			return fail()
		}
		info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		}
		if windows.SetSecurityInfo(p.process, windows.SE_KERNEL_OBJECT, info, nil, nil, acl, nil) != nil {
			return fail()
		}
		actual, e := descriptorText(p.process)
		if e != nil || actual != after.String() {
			return fail()
		}
		before = actual
	}
	p.descriptor = before
	if p.Check(ctx) != nil {
		return fail()
	}
	return p, nil
}
func (p *ServiceGuard) Check(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.process == 0 || !livePeerProcess(p.process) {
		return ErrPeer
	}
	current, e := descriptorText(p.process)
	if e != nil || current != p.descriptor || validateProcessDescriptor(current, p.config.ObserverReceipt.ServiceSID) != nil {
		return ErrPeer
	}
	if checkHeldExecutable(p.pins, p.config.Executable) != nil {
		return ErrPeer
	}
	snapshot, e := windowsservice.InspectOwned(ctx, p.config.ObserverReceipt)
	if e != nil || snapshot.State != windowsservice.Running {
		return ErrPeer
	}
	if e := checkUpdateServiceSCM(uint32(os.Getpid()), p.config.Executable); e != nil {
		return e
	}
	return ctx.Err()
}
func (p *ServiceGuard) Close() {
	if p == nil {
		return
	}
	for i := len(p.pins) - 1; i >= 0; i-- {
		windows.CloseHandle(p.pins[i])
	}
	p.pins = nil
	if p.process != 0 {
		windows.CloseHandle(p.process)
		p.process = 0
	}
}
