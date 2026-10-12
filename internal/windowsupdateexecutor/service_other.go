//go:build !windows

package windowsupdateexecutor

func VerifyServiceContext() error { return ErrUnavailable }
