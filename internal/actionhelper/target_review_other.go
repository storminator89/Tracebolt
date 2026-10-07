//go:build !linux

package actionhelper

import "context"

func DiscoverSetupTargetReview(context.Context) (SetupTargetReview, error) {
	return SetupTargetReview{}, ErrUnavailable
}
