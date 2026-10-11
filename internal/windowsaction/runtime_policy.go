package windowsaction

import (
	"context"
	"errors"
)

func serviceExitCode(stopping bool, runErr, closeErr error) uint32 {
	if !stopping || closeErr != nil || runErr != nil && !errors.Is(runErr, context.Canceled) {
		return 1
	}
	return 0
}
