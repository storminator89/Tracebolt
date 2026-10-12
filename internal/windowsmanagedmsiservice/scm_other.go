//go:build !windows

package windowsmanagedmsiservice

import (
	"context"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
)

func CheckAbsent(context.Context) error { return managed.ErrUnavailable }
func CreateDisabled(context.Context, windowsmanagedmsiipc.Config) error {
	return managed.ErrUnavailable
}
func CheckInstalled(context.Context, windowsmanagedmsiipc.Config, bool) error {
	return managed.ErrUnavailable
}
func Activate(context.Context, windowsmanagedmsiipc.Config) error { return managed.ErrUnavailable }
func Run(context.Context) error                                   { return managed.ErrUnavailable }
