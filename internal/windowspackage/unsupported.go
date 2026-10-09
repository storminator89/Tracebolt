//go:build !windows

package windowspackage

import "context"

func nativeSession(context.Context) (session, error) { return nil, ErrUnsupported }
