//go:build !windows

package windowssoftwareexecutor

func VerifyForegroundContext() error { return ErrUnavailable }
