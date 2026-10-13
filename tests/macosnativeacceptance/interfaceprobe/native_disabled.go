//go:build !darwin || !tracebolt_interface_diagnostics

package main

import (
	"context"

	"localrmm/internal/macosinventory"
)

const diagnosticBuild = false

func nativeCommand(context.Context, bool) ([]byte, error) {
	return nil, macosinventory.ErrUnsupported
}
