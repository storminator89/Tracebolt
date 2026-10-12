//go:build !windows

package windowsupdateservice

import (
	"context"
	"localrmm/internal/windowsupdateipc"
	managed "localrmm/internal/windowsupdatejob"
)

func CheckAbsent(context.Context) error { return managed.ErrUnavailable }
func CreateDisabled(context.Context, windowsupdateipc.Config) error {
	return managed.ErrUnavailable
}
func CheckInstalled(context.Context, windowsupdateipc.Config, bool) error {
	return managed.ErrUnavailable
}
func Activate(context.Context, windowsupdateipc.Config) error { return managed.ErrUnavailable }
func Run(context.Context) error                               { return managed.ErrUnavailable }
