package enrollmentstore

import (
	"context"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsmanagedmsi"
)

type windowsManagedMSISetupLeafKey struct{}
type windowsManagedMSISetupLeaf struct {
	digest   string
	notAfter int64
}

// WithWindowsManagedMSISetupExpectedLeaf adds the explicit setup caller's reviewed
// current transport leaf. It never substitutes for the original identity anchor
// in Consent. A renewal while apply waits requires a fresh read-only review.
func WithWindowsManagedMSISetupExpectedLeaf(ctx context.Context, digest string, notAfter int64) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, windowsManagedMSISetupLeafKey{}, windowsManagedMSISetupLeaf{digest, notAfter})
}
func checkWindowsManagedMSISetupExpectedLeaf(ctx context.Context, current windowsmanagedmsi.Current) error {
	expected, ok := ctx.Value(windowsManagedMSISetupLeafKey{}).(windowsManagedMSISetupLeaf)
	if !ok {
		return nil
	}
	if !actionpermit.ValidDigest(expected.digest) || expected.notAfter <= 0 || expected.notAfter > enrollmentstate.MaxTimestamp || expected.digest != current.LeafDigest || expected.notAfter != current.LeafNotAfter {
		return windowsmanagedmsi.ErrAuthority
	}
	return nil
}
