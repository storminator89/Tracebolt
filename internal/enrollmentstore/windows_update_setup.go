package enrollmentstore

import (
	"context"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsupdatejob"
)

type windowsUpdateSetupLeafKey struct{}
type windowsUpdateSetupLeaf struct {
	digest   string
	notAfter int64
}

// WithWindowsUpdateSetupExpectedLeaf adds the explicit setup caller's reviewed
// current transport leaf. It never substitutes for the original identity anchor
// in Consent. A renewal while apply waits requires a fresh read-only review.
func WithWindowsUpdateSetupExpectedLeaf(ctx context.Context, digest string, notAfter int64) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, windowsUpdateSetupLeafKey{}, windowsUpdateSetupLeaf{digest, notAfter})
}
func checkWindowsUpdateSetupExpectedLeaf(ctx context.Context, current windowsupdatejob.Current) error {
	expected, ok := ctx.Value(windowsUpdateSetupLeafKey{}).(windowsUpdateSetupLeaf)
	if !ok {
		return nil
	}
	if !actionpermit.ValidDigest(expected.digest) || expected.notAfter <= 0 || expected.notAfter > enrollmentstate.MaxTimestamp || expected.digest != current.LeafDigest || expected.notAfter != current.LeafNotAfter {
		return windowsupdatejob.ErrAuthority
	}
	return nil
}
