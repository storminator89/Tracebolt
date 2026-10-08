//go:build windows && tracebolt_fresh_native

package native

import (
	"context"
	"localrmm/internal/windowsservice"
)

// VerifyFreshServiceToken is read-only and test-build-only. It accepts an exact
// completed production receipt, never installs it into the legacy driver.
func VerifyFreshServiceToken(ctx context.Context, r windowsservice.Receipt) error {
	if ctx == nil || ctx.Err() != nil || !r.Complete || r.Version != 1 {
		return ErrAcceptance
	}
	s, e := windowsservice.InspectOwned(ctx, r)
	if e != nil || s.State != windowsservice.Running || s.ProcessID == 0 || !validateProcessToken(s.ProcessID, r.ServiceSID, "") {
		return ErrAcceptance
	}
	again, e := windowsservice.InspectOwned(ctx, r)
	if e != nil || again.State != windowsservice.Running || again.ProcessID != s.ProcessID {
		return ErrAcceptance
	}
	return nil
}

// ReleaseFreshProvisioning closes only read handles. New app-owned files and
// partial native state remain for the explicitly approved disposable-VM policy.
func (d *Driver) ReleaseFreshProvisioning() {
	if d != nil {
		if s, ok := d.native(); ok {
			s.releaseObjectPins()
		}
		d.releasePrerequisiteHandles()
	}
}
