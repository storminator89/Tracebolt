//go:build windows

package native

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsagentconfig"
	"path/filepath"
)

func (d *Driver) configureCapabilities(ctx context.Context, g Guard) error {
	s, ok := d.native()
	if !ok || !d.evidence.Ready || !s.sender.seen || !d.verifyReceipt() || !d.requireStopped(ctx) {
		return d.fail(ReasonState)
	}
	// Re-read the original claim and durable sender, rather than trusting cached
	// Ready/Stopped booleans. Neither approval nor a grant may replace identity.
	if d.stateContinuity(ctx) != nil || !d.evidence.Ready || !d.evidence.SenderFloorRetained {
		return d.fail(ReasonState)
	}
	before := s.sender
	for _, c := range capabilityStores() {
		path := s.layout.StateRoot + c.suffix
		if _, known := s.recordedRoot(path); known || !absent(path) {
			return d.fail(ReasonExisting)
		}
	}
	for _, c := range capabilityStores() {
		if !approved(ctx, g) {
			return d.fail(ReasonGuard)
		}
		if !d.verifyReceipt() || !d.requireStopped(ctx) {
			return d.fail(ReasonOwnership)
		}
		if !absent(s.layout.StateRoot + c.suffix) {
			return d.fail(ReasonExisting)
		}
		if !approved(ctx, g) {
			return d.fail(ReasonGuard)
		}
		result, err := lanclient.ConfigureWindowsCapabilities(filepath.Join(s.layout.EnrollmentRoot, "agent.json"), c.consent(d.options.Selection.HTTPTest()))
		// A failed operation can have committed bytes. Do not capture/adopt its
		// directory: the unknown sibling intentionally fences cleanup for review.
		if err != nil || !result.MetadataScopeVerified || result.FailedScope != "" || len(result.AppliedScopes) != 1 || result.AppliedScopes[0] != c.scope {
			return d.fail(ReasonState)
		}
		if s.captureRoot(s.layout.StateRoot+c.suffix) != nil {
			return d.fail(ReasonOwnership)
		}
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	if d.stateContinuity(ctx) != nil || !d.evidence.Ready || s.sender != before {
		return d.fail(ReasonOwnership)
	}
	return nil
}

// snapshotRetainedState extends uninstall's exact before/after proof only with
// sibling roots this invocation successfully created and recorded.
func (d *Driver) snapshotRetainedState() ([]ownedObject, error) {
	s, ok := d.native()
	if !ok {
		return nil, ErrAcceptance
	}
	out, err := snapshotStore(s.layout.StateRoot, windowsagentconfig.RuntimeRoot(d.receipt.ServiceSID, false))
	if err != nil {
		return nil, err
	}
	if !d.options.Expanded {
		return out, nil
	}
	for _, c := range capabilityStores() {
		path := s.layout.StateRoot + c.suffix
		id, known := s.recordedRoot(path)
		if !known {
			if !absent(path) {
				return nil, ErrAcceptance
			}
			continue
		}
		records, err := snapshotStore(path, c.options(d.receipt.ServiceSID))
		if err != nil || len(records) == 0 || records[0].id != id {
			return nil, ErrAcceptance
		}
		out = append(out, records...)
	}
	return out, nil
}
