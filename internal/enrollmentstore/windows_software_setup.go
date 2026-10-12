package enrollmentstore

import (
	"context"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowssoftwarejob"
)

type windowsSoftwareSetupLeafKey struct{}
type windowsSoftwareSetupLeaf struct {
	digest   string
	notAfter int64
}

// WithWindowsSoftwareSetupExpectedLeaf adds the explicit setup caller's reviewed
// current transport leaf. It never substitutes for the original identity anchor
// in Consent. A renewal while apply waits requires a fresh read-only review.
func WithWindowsSoftwareSetupExpectedLeaf(ctx context.Context, digest string, notAfter int64) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, windowsSoftwareSetupLeafKey{}, windowsSoftwareSetupLeaf{digest, notAfter})
}
func checkWindowsSoftwareSetupExpectedLeaf(ctx context.Context, current windowssoftwarejob.Current) error {
	expected, ok := ctx.Value(windowsSoftwareSetupLeafKey{}).(windowsSoftwareSetupLeaf)
	if !ok {
		return nil
	}
	if !actionpermit.ValidDigest(expected.digest) || expected.notAfter <= 0 || expected.notAfter > enrollmentstate.MaxTimestamp || expected.digest != current.LeafDigest || expected.notAfter != current.LeafNotAfter {
		return windowssoftwarejob.ErrAuthority
	}
	return nil
}
