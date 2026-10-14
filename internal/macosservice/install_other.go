//go:build !darwin

package macosservice

import "context"

func VerifyNativeLaunchdAbsence(context.Context) error { return ErrUnavailable }
