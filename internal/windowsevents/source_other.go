//go:build !windows

package windowsevents

import "context"

// Collect returns ErrUnsupported on non-Windows systems and performs no reads.
func Collect(ctx context.Context, channels []string, limit int) (Report, error) {
	return collectWith(ctx, channels, limit, func(context.Context, string) (cursor, error) {
		return nil, ErrUnsupported
	})
}
