//go:build darwin && tracebolt_interface_diagnostics

package main

import (
	"context"

	"localrmm/internal/macosinventory"
)

const diagnosticBuild = true

func nativeCommand(ctx context.Context, ipv6 bool) ([]byte, error) {
	return macosinventory.RunInterfaceDiagnosticCommand(ctx, ipv6)
}
