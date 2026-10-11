//go:build !windows

package windowsusersoftwarelocal

import "context"

func Serve(context.Context, Handler) error { return ErrUnavailable }
func RunForeground(context.Context, func(context.Context, Challenge) bool) error {
	return ErrUnavailable
}
func IsForegroundConsole() bool { return false }
