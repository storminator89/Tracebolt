//go:build darwin && tracebolt_interface_diagnostics

package macosinventory

import "context"

// RunInterfaceDiagnosticCommand is compiled only for the explicitly tagged
// native evidence probe. It is not an endpoint provider, grant or product API.
// The manual supervisor must admit exact reviewed source before calling it.
func RunInterfaceDiagnosticCommand(ctx context.Context, ipv6 bool) ([]byte, error) {
	return runInterfaceDiagnosticCommand(ctx, ipv6, runFixedCommand)
}
