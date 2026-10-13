//go:build tracebolt_interface_diagnostics

package macosinventory

import (
	"context"
	"reflect"
	"testing"
)

func TestDiagnosticBridgeUsesOnlyFixedInterfaceCommands(t *testing.T) {
	var commands []fixedCommand
	run := func(ctx context.Context, which fixedCommand) ([]byte, error) {
		if ctx == nil {
			t.Fatal("missing context")
		}
		commands = append(commands, which)
		spec, err := specification(which)
		if err != nil || spec.path != "/sbin/ifconfig" || spec.maxBytes != MaxSourceBytes {
			t.Fatal("not fixed ifconfig")
		}
		family := "inet"
		if which == ipv6Command {
			family = "inet6"
		}
		if !reflect.DeepEqual(spec.args, []string{"-a", family}) {
			t.Fatal("wrong fixed args")
		}
		return []byte("inert"), nil
	}
	for _, ipv6 := range []bool{false, true} {
		if _, err := runInterfaceDiagnosticCommand(context.Background(), ipv6, run); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(commands, []fixedCommand{ipv4Command, ipv6Command}) {
		t.Fatal("extra or reordered command")
	}
}

func TestDiagnosticBridgeCancellationAndInvalidInputsDoNotRun(t *testing.T) {
	run := func(context.Context, fixedCommand) ([]byte, error) { t.Fatal("must not run"); return nil, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runInterfaceDiagnosticCommand(ctx, false, run); err != ErrBudget {
		t.Fatal("cancellation")
	}
	if _, err := runInterfaceDiagnosticCommand(nil, false, run); err != ErrInvalid {
		t.Fatal("nil context")
	}
	if _, err := runInterfaceDiagnosticCommand(context.Background(), false, nil); err != ErrInvalid {
		t.Fatal("nil runner")
	}
}
