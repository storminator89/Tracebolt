//go:build !linux

package endpointidentity

import (
	"context"
	"time"
)

func Collect(ctx context.Context, generation string, at time.Time, consent LocalConsent, currentBinding string) (Snapshot, error) {
	if ctx == nil || !generationPattern.MatchString(generation) || !validTime(at) {
		return Snapshot{}, ErrInvalidInput
	}
	if _, e := EncodeLocalConsent(consent, currentBinding); e != nil {
		return Snapshot{}, ErrInvalidInput
	}
	return Empty(generation, at, ReasonNotSupported), nil
}
