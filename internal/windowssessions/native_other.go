//go:build !windows

package windowssessions

import "context"

func nativeSessions(context.Context) (Sessions, error) { return Sessions{}, ErrUnsupported }
func nativeJoin(context.Context) (Join, error)         { return Join{}, ErrUnsupported }
