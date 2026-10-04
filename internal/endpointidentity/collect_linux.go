//go:build linux

package endpointidentity

import (
	"context"
	"time"
)

// Collect requires a current, explicitly acknowledged local declaration before
// constructing any OS provider. The runtime owns protected file validation and
// current identity/activation authorization; this is not OS/admin attestation.
func Collect(ctx context.Context, generation string, at time.Time, consent LocalConsent, currentBinding string) (Snapshot, error) {
	if _, e := EncodeLocalConsent(consent, currentBinding); e != nil {
		return Snapshot{}, ErrInvalidInput
	}
	return CollectWithProvider(ctx, generation, at, newLinuxProvider())
}
