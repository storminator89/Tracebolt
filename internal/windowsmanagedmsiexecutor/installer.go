// Package windowsmanagedmsiexecutor owns native MSI calls only inside the fresh
// LocalSystem deployment service. The observer never imports this package.
package windowsmanagedmsiexecutor

import (
	"context"
	"encoding/json"
	"errors"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowspackage"
	"time"
)

type Installer struct{ coordinated bool }

func NewCoordinatedInstaller() managed.Installer { return Installer{coordinated: true} }

func NewInstaller() managed.Installer { return Installer{} }
func receipt(raw json.RawMessage, s managed.Selection) (windowspackage.ManagedMSIReceipt, error) {
	var r windowspackage.ManagedMSIReceipt
	if managed.Canonical(raw, &r, 4096) != nil || r.Validate() != nil || r.Package != s {
		return r, managed.ErrIntegrity
	}
	return r, nil
}
func (i Installer) Inspect(ctx context.Context, raw json.RawMessage, s managed.Selection, until int64) (managed.Readiness, error) {
	if i.coordinated {
		ctx = windowspackage.RequireSynchronousMSI(ctx)
	}
	r, e := receipt(raw, s)
	if e != nil {
		return managed.Readiness{}, e
	}
	a, e := New(r, time.Unix(until, 0))
	if e != nil {
		return managed.Readiness{}, e
	}
	p, e := a.PrepareExact(ctx, s)
	if e != nil {
		return managed.Readiness{}, e
	}
	return inspectPrepared(ctx, p)
}
func (i Installer) Install(ctx context.Context, raw json.RawMessage, ready managed.Readiness) (managed.NativeResult, error) {
	unknown := managed.NativeResult{RegistrationVerified: managed.Unknown}
	if i.coordinated {
		ctx = windowspackage.RequireSynchronousMSI(ctx)
	}
	r, e := receipt(raw, ready.Selection)
	if e != nil {
		return unknown, e
	}
	a, e := New(r, time.Unix(ready.MaintenanceWindowEnd, 0))
	if e != nil {
		return unknown, e
	}
	p, e := a.PrepareExact(ctx, ready.Selection)
	if e != nil {
		return unknown, e
	}
	return installPrepared(ctx, p, ready)
}
func installPrepared(ctx context.Context, p managed.PreparedPackage, ready managed.Readiness) (result managed.NativeResult, err error) {
	unknown := managed.NativeResult{RegistrationVerified: managed.Unknown}
	defer func() {
		if e := p.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	fresh, e := p.Inspect(ctx)
	if e != nil || fresh.Reason() != "ready" || !managed.SameReadinessFacts(fresh, ready) {
		return unknown, managed.ErrAuthority
	}
	return p.InstallOnce(ctx)
}

func inspectPrepared(ctx context.Context, p managed.PreparedPackage) (result managed.Readiness, err error) {
	defer func() {
		if e := p.Close(); e != nil {
			result = managed.Readiness{}
			err = errors.Join(err, e)
		}
	}()
	return p.Inspect(ctx)
}
