//go:build !linux

package actionhelper

import (
	"context"
	"crypto/ed25519"
)

func beginSetupInitialization(context.Context, Policy, ed25519.PublicKey) error {
	return ErrUnavailable
}
func CheckSetupTargetFile(context.Context, string) (SetupTargetResult, error) {
	return SetupTargetResult{}, ErrUnavailable
}
