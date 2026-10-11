package windowsupdates

import (
	"context"
	"errors"
	"localrmm/internal/windowspatchcontext"
	"math"
	"time"
)

// CollectPatchContext is a separate grant/worker path. It never invokes Search.
// Sharing the small COM decoder does not promote the existing cache grant.
func CollectPatchContext(ctx context.Context, req windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
	return windowspatchcontext.CollectWithSources(ctx, req, openPatchNative, windowspatchcontext.NativeMachine)
}
func patchError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, ErrDenied):
		return windowspatchcontext.ErrDenied
	case errors.Is(e, ErrUnsupported):
		return windowspatchcontext.ErrUnsupported
	case errors.Is(e, ErrMetadata):
		return windowspatchcontext.ErrMetadata
	case errors.Is(e, ErrBounds):
		return windowspatchcontext.ErrBounds
	case errors.Is(e, ErrOffline):
		return windowspatchcontext.ErrOffline
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	default:
		return windowspatchcontext.ErrUnavailable
	}
}

// MS-UAMG specifies UTC. Accept positive OLE dates only, in the supported
// 1970..9999 range, and round to milliseconds without overflowing Duration.
func patchDate(days float64) (time.Time, error) {
	if math.IsNaN(days) || math.IsInf(days, 0) || days < 25569 || days >= 2958466 {
		return time.Time{}, windowspatchcontext.ErrMetadata
	}
	ms := math.Round((days - 25569) * 86400000)
	t := time.UnixMilli(int64(ms)).UTC()
	if t.Year() < 1970 || t.Year() > 9999 {
		return time.Time{}, windowspatchcontext.ErrMetadata
	}
	return t, nil
}
