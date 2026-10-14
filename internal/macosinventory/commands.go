package macosinventory

import "context"

type fixedCommand uint8

const (
	hardwareCommand fixedCommand = iota
	receiptsCommand
	processesCommand
	ipv4Command
	ipv6Command
)

type commandSpec struct {
	path     string
	args     []string
	maxBytes int
}

func specification(which fixedCommand) (commandSpec, error) {
	switch which {
	case hardwareCommand:
		return commandSpec{"/usr/sbin/sysctl", []string{"-n", "hw.model", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"}, 4096}, nil
	case receiptsCommand:
		return commandSpec{"/usr/sbin/pkgutil", []string{"--pkgs-plist"}, MaxSourceBytes}, nil
	case processesCommand:
		return commandSpec{"/bin/ps", []string{"-A", "-o", "ucomm=,pid=,ppid="}, MaxSourceBytes}, nil
	case ipv4Command:
		return commandSpec{"/sbin/ifconfig", []string{"-a", "inet"}, MaxSourceBytes}, nil
	case ipv6Command:
		return commandSpec{"/sbin/ifconfig", []string{"-a", "inet6"}, MaxSourceBytes}, nil
	}
	return commandSpec{}, ErrInvalid
}

type commandRunner func(context.Context, fixedCommand) ([]byte, error)

func commandSources(run commandRunner) Sources {
	return Sources{
		Hardware: func(ctx context.Context) (Hardware, error) {
			b, e := run(ctx, hardwareCommand)
			if e != nil {
				return Hardware{}, e
			}
			return ParseHardware(b)
		},
		Receipts: func(ctx context.Context) (Receipts, error) {
			b, e := run(ctx, receiptsCommand)
			if e != nil {
				return Receipts{}, e
			}
			return ParseReceipts(b)
		},
		Processes: func(ctx context.Context) (Processes, error) {
			b, e := run(ctx, processesCommand)
			if e != nil {
				return Processes{}, e
			}
			return ParseProcesses(b)
		},
		Network: func(ctx context.Context) (Network, error) {
			n := EmptyNetwork(ErrUnavailable.Error())
			// The network source has one shared provider deadline. Skip a native
			// family read when that deadline (or caller cancellation) is known.
			// A completed sibling still keeps its independently observed value.
			if ctx.Err() != nil {
				return EmptyNetwork(ErrBudget.Error()), nil
			}
			b, e := run(ctx, ipv4Command)
			if e == nil {
				n.IPv4, e = ParseInterfaces(b, false)
			}
			if e != nil {
				n.IPv4 = EmptyInterfaces(IPv4Source, SafeReason(e))
			}
			if ctx.Err() != nil {
				n.IPv6 = EmptyInterfaces(IPv6Source, ErrBudget.Error())
				return n, nil
			}
			b, e = run(ctx, ipv6Command)
			if e == nil {
				n.IPv6, e = ParseInterfaces(b, true)
			}
			if e != nil {
				n.IPv6 = EmptyInterfaces(IPv6Source, SafeReason(e))
			}
			return n, nil
		},
	}
}
