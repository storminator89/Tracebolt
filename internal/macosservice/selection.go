package macosservice

import (
	"context"
	"reflect"
	"strings"
)

// SelectionEvidence is emitted only by the fixed-path nonroot child on macOS.
// It contains no key, certificate or telemetry. It is a fresh observation,
// never reusable permission to mutate a host.
type SelectionEvidence struct {
	Config                 []byte `json:"config"`
	EnrollmentAnchorSHA256 string `json:"enrollmentAnchorSHA256"`
}

// inspectWithRegisteredHandoff makes the lock transition explicit and testable.
// Lock contention alone never chooses the no-lock branch; exact preexisting
// owner/plist/job/started-receipt evidence must do so first.
func inspectWithRegisteredHandoff(ctx context.Context, r Request, s InstallSnapshot, inspect func(context.Context, Request, bool) (SelectionEvidence, error)) (SelectionEvidence, error) {
	if inspect == nil || ctx == nil || ctx.Err() != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	return inspect(ctx, r, allowRegisteredHandoff(r, s))
}

// inspectStableSelection brackets the potentially 30-second nonroot child with
// exact protected native observations. Neither a child success nor the held
// installer descriptor may turn an earlier job/plist/custody read into current
// evidence after an external launchd or filesystem change.
func inspectStableSelection(ctx context.Context, r Request, observe func(context.Context) (InstallSnapshot, error), inspect func(context.Context, Request, bool) (SelectionEvidence, error)) (InstallSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || observe == nil {
		return InstallSnapshot{}, ErrPreflight
	}
	before, err := observe(ctx)
	if err != nil {
		return InstallSnapshot{}, ErrPreflight
	}
	evidence, err := inspectWithRegisteredHandoff(ctx, r, before, inspect)
	if err != nil || ctx.Err() != nil {
		return InstallSnapshot{}, ErrPreflight
	}
	after, err := observe(ctx)
	if err != nil || ctx.Err() != nil || !reflect.DeepEqual(before, after) {
		return InstallSnapshot{}, ErrPreflight
	}
	after.PrerequisitesVerified = true
	after.Config = evidence.Config
	after.EnrollmentAnchorSHA256 = evidence.EnrollmentAnchorSHA256
	return after, nil
}

// The lifecycle child may legitimately see an already published plist. Its
// held directory checks must still run; plist presence cannot short-circuit
// them. Unknown plist status is never positive evidence.
func finalSelectionPaths(plistKnown, plistAbsent, requireAbsent bool, stable func() bool) bool {
	return plistKnown && stable != nil && stable() && (!requireAbsent || plistAbsent)
}

func mutableSelectionDirectory(name string, registeredHandoff bool) bool {
	return registeredHandoff && (name == StateDirectory || strings.HasPrefix(name, StateDirectory+"/"))
}
