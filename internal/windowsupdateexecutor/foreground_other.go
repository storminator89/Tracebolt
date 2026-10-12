//go:build !windows

package windowsupdateexecutor

func VerifyForegroundContext() error { return ErrUnavailable }
