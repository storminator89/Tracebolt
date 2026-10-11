//go:build !windows

package windowseventhistory

import "context"

func readSearch(ctx context.Context, search Search) (Report, error) {
	return searchWith(ctx, search, func(context.Context, Search) (cursor, error) { return nil, ErrUnsupported })
}
