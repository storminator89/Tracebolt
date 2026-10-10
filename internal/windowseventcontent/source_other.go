//go:build !windows

package windowseventcontent

import "context"

// Read returns a bounded unavailable report on non-Windows, without host reads.
func Read(ctx context.Context, request Request) (Report, error) {
	return readWith(ctx, request, func(context.Context, Event) (cursor, error) { return nil, ErrUnsupported })
}
