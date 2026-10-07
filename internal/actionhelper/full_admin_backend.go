package actionhelper

import (
	"context"
	"localrmm/internal/actionpermit"
)

type fullAdminSystemdBackend struct{ source fullAdminSource }

func (b *fullAdminSystemdBackend) InspectService(ctx context.Context, unit string) (ServiceInspection, error) {
	return inspectServiceV2(ctx, b.source, unit)
}
func (b *fullAdminSystemdBackend) ListServices(ctx context.Context) ([]string, error) {
	if _, err := b.source.file(systemctlPath); err != nil {
		return nil, err
	}
	raw, err := b.source.run(ctx, targetListArgs())
	if err != nil {
		return nil, err
	}
	listed, err := parseListedServices(raw)
	if err != nil || len(listed) > MaxServicesV2 {
		return nil, ErrRejected
	}
	return listed, nil
}
func (b *fullAdminSystemdBackend) Check(ctx context.Context, t Target) (Observation, error) {
	if len(t.Units) != 0 || len(t.Inputs) != 0 || !actionpermit.ValidDigest(t.ReviewDigest) || !actionpermit.ValidDigest(t.AffectedServicesDigest) {
		return Unknown, ErrRejected
	}
	inspection, err := b.InspectService(ctx, t.Unit)
	if err != nil || inspection.UnitPolicyDigest != t.ReviewDigest {
		return Unknown, ErrRejected
	}
	impact, err := actionpermit.AffectedServicesDigest(inspection.AffectedServices)
	if err != nil || impact != t.AffectedServicesDigest {
		return Unknown, ErrRejected
	}
	return inspection.ObservedState, nil
}
func (b *fullAdminSystemdBackend) TryRestart(ctx context.Context, unit string) error {
	if !canonicalUnit(unit) || protectedFullAdminUnit(unit) {
		return ErrRejected
	}
	_, err := b.source.run(ctx, systemctlArgs("try-restart", unit, nil))
	return err
}
func (b *fullAdminSystemdBackend) Observe(ctx context.Context, unit string) (Observation, error) {
	if !canonicalUnit(unit) || protectedFullAdminUnit(unit) {
		return Unknown, ErrRejected
	}
	raw, err := b.source.run(ctx, systemctlArgs("show", unit, []string{"Id", "ActiveState"}))
	if err != nil {
		return Unknown, err
	}
	p, err := parseProperties(raw, []string{"Id", "ActiveState"})
	if err != nil || p["Id"] != unit {
		return Unknown, ErrRejected
	}
	switch p["ActiveState"] {
	case "active":
		return Active, nil
	case "inactive":
		return Inactive, nil
	case "failed":
		return Failed, nil
	}
	return Unknown, nil
}
