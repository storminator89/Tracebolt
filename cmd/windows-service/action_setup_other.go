//go:build !windows

package main

import "context"

func nativeActionSetup(context.Context, actionSetupInput) error { return errLifecycle }
