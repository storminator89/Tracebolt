package windowsmanagedmsiexecutor

import (
	"context"
	job "localrmm/internal/windowsmanagedmsi"
	"time"
)

// The private seam carries fixed operations only. Neither package paths nor MSI
// properties can arrive through the signed command/observer/manager surfaces.
type nativeRuntime interface {
	prepare(context.Context, job.Selection) error
	verify(context.Context) error
	machineAbsent(context.Context, job.Selection) job.Fact
	installerBusy(context.Context) job.Fact
	install(context.Context) (uint32, error)
	registration(context.Context, job.Selection) job.Fact
	verifyToken() error
	close() error
}
type engine struct {
	native           nativeRuntime
	selection        job.Selection
	now              func() time.Time
	checkStart       func(context.Context, time.Time) error
	maintenanceUntil int64
	reviewed         *job.Readiness
	attempted        bool
}

func (e *engine) prepare(ctx context.Context) error { return e.native.prepare(ctx, e.selection) }
func (e *engine) inspect(ctx context.Context) (job.Readiness, error) {
	r := job.Readiness{Selection: e.selection, CapturedAt: e.now().UTC().Unix(), PackageVerified: job.Unknown, MachineAbsent: job.Unknown, InstallerBusy: job.Unknown, NativeAcceptance: job.Unknown, PackageReviewAccepted: job.Unknown, MaintenanceWindowEnd: e.maintenanceUntil}
	if err := e.native.verifyToken(); err != nil {
		return r, err
	}
	if err := e.native.verify(ctx); err != nil {
		return r, err
	}
	r.PackageVerified, r.NativeAcceptance, r.PackageReviewAccepted = job.Yes, job.Yes, job.Yes
	r.MachineAbsent = e.native.machineAbsent(ctx, e.selection)
	r.InstallerBusy = e.native.installerBusy(ctx)
	r.CapturedAt = e.now().UTC().Unix()
	if err := ctx.Err(); err != nil {
		return r, err
	}
	return r, nil
}
func (e *engine) installOnce(ctx context.Context) (job.NativeResult, error) {
	unknown := job.NativeResult{RegistrationVerified: job.Unknown}
	if e.attempted {
		return unknown, ErrClosed
	}
	e.attempted = true
	if e.reviewed == nil || e.reviewed.Reason() != "ready" {
		return unknown, ErrReadiness
	}
	r, err := e.inspect(ctx)
	if err != nil {
		return unknown, err
	}
	if r.Reason() != "ready" || !job.SameReadinessFacts(r, *e.reviewed) {
		return unknown, ErrReadiness
	}
	if e.checkStart == nil {
		return unknown, job.ErrAuthority
	}
	if err = e.checkStart(ctx, e.now()); err != nil {
		return unknown, err
	}
	// The maintenance gate is a bounded administrator assertion. It does not lock
	// WUA, SCM, or another installer. A racing MSI may return1618; it is consumed.
	if e.now().UTC().Unix() >= e.maintenanceUntil {
		return unknown, job.ErrExpired
	}
	code, err := e.native.install(ctx)
	result := job.NativeResult{ReturnCode: code, ReturnCodeKnown: err == nil, RegistrationVerified: job.Unknown}
	if err != nil {
		return result, err
	}
	result.RegistrationVerified = e.native.registration(ctx, e.selection)
	if err = ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}
