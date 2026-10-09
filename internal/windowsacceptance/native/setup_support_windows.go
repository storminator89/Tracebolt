//go:build windows && tracebolt_setup_native

package native

import (
	"context"
	"localrmm/internal/windowsservice"
)

// VerifySetupServiceToken observes only the actual receipt-owned running service
// token. This helper is absent from ordinary builds and cannot change privileges.
func VerifySetupServiceToken(ctx context.Context, r windowsservice.Receipt) error {
	if ctx == nil || ctx.Err() != nil || !r.Complete || r.Version != 1 {
		return ErrAcceptance
	}
	s, e := windowsservice.InspectOwned(ctx, r)
	if e != nil || s.State != windowsservice.Running || !validateProcessToken(s.ProcessID, r.ServiceSID, "") {
		return ErrAcceptance
	}
	a, e := windowsservice.InspectOwned(ctx, r)
	if e != nil || a.State != windowsservice.Running || a.ProcessID != s.ProcessID {
		return ErrAcceptance
	}
	return nil
}
