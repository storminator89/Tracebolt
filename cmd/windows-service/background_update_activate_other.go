//go:build !windows

package main

import (
	"context"
	job "localrmm/internal/windowsupdatejob"
)

func nativeBackgroundUpdateActivate(context.Context, string, job.BackgroundActivation) error {
	return job.ErrUnavailable
}
