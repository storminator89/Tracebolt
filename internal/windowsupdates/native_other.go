//go:build !windows

package windowsupdates

import "context"

func openNative(context.Context) (Source, error) { return nil, ErrUnsupported }
