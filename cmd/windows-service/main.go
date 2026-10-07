// Command windows-service is a guarded source candidate for the Windows basic
// TLS lifecycle. Applying installation or enrollment requires local approval;
// tests must use injected operations, never the native implementation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"localrmm/internal/windowsservice"
)

type request struct{ mode, bootstrap string }
type operation func(context.Context, request, io.Writer, io.Writer) (any, error)

func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	return runWith(ctx, args, out, stderr, nativeOperation)
}
func runWith(ctx context.Context, args []string, out, stderr io.Writer, perform operation) int {
	flags := flag.NewFlagSet("windows-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	names := []string{"plan", "inspect", "install", "enroll", "start", "stop", "uninstall", "run-service"}
	modes := map[string]*bool{}
	for _, n := range names {
		modes[n] = flags.Bool(n, false, "")
	}
	apply := flags.Bool("apply", false, "")
	consent := flags.Bool("basic-readonly", false, "")
	bootstrap := flags.String("bootstrap-file", "", "")
	help := flags.Bool("help", false, "")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(out)
			return 0
		}
		fmt.Fprintln(stderr, "Unsupported Windows lifecycle arguments; use --help.")
		return 2
	}
	if *help {
		usage(out)
		return 0
	}
	mode := ""
	for _, n := range names {
		if *modes[n] {
			if mode != "" {
				fmt.Fprintln(stderr, "Choose exactly one Windows lifecycle operation.")
				return 2
			}
			mode = n
		}
	}
	mutate := mode == "install" || mode == "enroll" || mode == "start" || mode == "stop" || mode == "uninstall"
	needsConsent := mode == "install" || mode == "enroll"
	if flags.NArg() != 0 || mode == "" || *apply != mutate || *consent != needsConsent || (mode == "install") != (*bootstrap != "") {
		fmt.Fprintln(stderr, "Operation flags rejected. Review --help; explicit apply and basic scope acknowledgement are required where stated.")
		return 2
	}
	if ctx == nil || perform == nil {
		reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonInvalidConfiguration, nil))
		return 1
	}
	result, err := perform(ctx, request{mode: mode, bootstrap: *bootstrap}, out, stderr)
	if err != nil {
		reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonOperationFailed, err))
		fmt.Fprintln(stderr, "Preserve the service and protected state for inspection; no reset or automatic cleanup was performed.")
		return 1
	}
	if result != nil {
		data, err := json.Marshal(result)
		if err != nil || len(data) > 64<<10 {
			reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonResultEncoding, err))
			return 1
		}
		data = append(data, '\n')
		n, err := out.Write(data)
		if err != nil || n != len(data) {
			reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonResultWrite, err))
			return 1
		}
	}
	return 0
}
func usage(out io.Writer) {
	fmt.Fprintln(out, "Tracebolt Windows basic TLS service source candidate. No Windows installation/reboot acceptance is established.")
	fmt.Fprintln(out, "Read only: --plan | --inspect")
	fmt.Fprintln(out, "Approved initial setup: --install --apply --basic-readonly --bootstrap-file ABSOLUTE_PROTECTED_PUBLIC_BOOTSTRAP")
	fmt.Fprintln(out, "Resume stopped enrollment: --enroll --apply --basic-readonly")
	fmt.Fprintln(out, "Approved lifecycle: --start --apply | --stop --apply | --uninstall --apply")
	fmt.Fprintln(out, "SCM-only runtime: --run-service (rejects an ordinary console)")
	fmt.Fprintln(out, "Installation creates one LocalService SCM service, a scoped service SID and protected durable state, then asks for a hidden invitation and starts pending enrollment. Review these persistent changes and obtain action-time approval before applying. Public fingerprint/comparison approval in the manager remains mandatory.")
	fmt.Fprintln(out, "Basic scope: bounded OS, uptime, physical RAM and system-volume observation. No expanded hostname/IP/process/software/event content collection, Windows Update/CVE, remote commands or service-control requests from a manager. Production TLS and basic-readonly-v1 only; Linux v3 profiles are rejected.")
	fmt.Fprintln(out, "Prerequisites: separately authorized provisioning of the fixed protected executable/parent directories, explicit LocalService read/execute access, and an administrator-only protected public bootstrap file. This candidate does not download/copy binaries, repair ACLs, enable privileges, adopt services or erase identities. Uninstall retains all private state.")
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
