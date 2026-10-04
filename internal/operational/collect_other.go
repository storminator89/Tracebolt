//go:build !linux

package operational

import (
	"context"
	"time"
)

func collectPlatform(_ context.Context, now time.Time) Snapshot {
	return Empty(now, ReasonNotSupported)
}
