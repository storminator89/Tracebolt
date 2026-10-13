//go:build tracebolt_interface_diagnostics

package macosinventory

import "context"

// This test-only bridge admits precisely one fixed interface family command.
// It accepts no path or arguments and shares the production runner unchanged.
func runInterfaceDiagnosticCommand(ctx context.Context, ipv6 bool, run commandRunner) ([]byte, error) {
	if ctx == nil || run == nil {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrBudget
	}
	which := ipv4Command
	if ipv6 {
		which = ipv6Command
	}
	return run(ctx, which)
}
