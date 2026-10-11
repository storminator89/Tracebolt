//go:build !windows

package windowsupdates

import (
	"context"
	"localrmm/internal/windowspatchcontext"
)

func openPatchNative(context.Context) (windowspatchcontext.Source, error) {
	return nil, windowspatchcontext.ErrUnsupported
}
