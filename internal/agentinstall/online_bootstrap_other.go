//go:build !linux

package agentinstall

import "context"

func ValidateOnlineBootstrapPreparation(context.Context, Request) error { return ErrPreflight }
