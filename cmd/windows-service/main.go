// Command windows-service is a guarded source candidate for explicitly selected Windows
// profiles. Applying installation or enrollment requires local approval;
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

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsvolumes"
	"path/filepath"
)

type request struct {
	mode, bootstrap, collectionProfile string
	insecureHTTP                       bool
}
type operation func(context.Context, request, io.Writer, io.Writer) (any, error)

func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	return runWith(ctx, args, out, stderr, nativeOperation)
}
func runWith(ctx context.Context, args []string, out, stderr io.Writer, perform operation) int {
	flags := flag.NewFlagSet("windows-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	names := []string{"plan", "inspect", "install", "enroll", "start", "stop", "uninstall", "run-service", "events-preview", "events-enable", "events-disable", "volumes-preview", "volumes-enable", "volumes-disable", "process-metrics-preview", "process-metrics-enable", "process-metrics-disable", "network-preview", "network-enable", "network-disable"}
	modes := map[string]*bool{}
	for _, n := range names {
		modes[n] = flags.Bool(n, false, "")
	}
	apply := flags.Bool("apply", false, "")
	consent := flags.Bool("basic-readonly", false, "")
	networkConsent := flags.Bool("network-endpoints", false, "")
	processMetricsConsent := flags.Bool("process-cpu-memory", false, "")
	volumeConsent := flags.Bool("visible-volumes", false, "")
	eventConsent := flags.Bool("application-system-event-headers", false, "")
	windowsConsent := flags.Bool("windows-inventory", false, "")
	insecure := flags.Bool("insecure-http-test", false, "")
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
	networkMode := mode == "network-preview" || mode == "network-enable" || mode == "network-disable"
	processMetricsMode := mode == "process-metrics-preview" || mode == "process-metrics-enable" || mode == "process-metrics-disable"
	mutate := mode == "network-enable" || mode == "network-disable" || mode == "process-metrics-enable" || mode == "process-metrics-disable" || mode == "install" || mode == "enroll" || mode == "start" || mode == "stop" || mode == "uninstall" || mode == "events-enable" || mode == "events-disable" || mode == "volumes-enable" || mode == "volumes-disable"
	needsConsent := mode == "install" || mode == "enroll"
	if *networkConsent != (mode == "network-enable") || *processMetricsConsent != (mode == "process-metrics-enable") || *volumeConsent != (mode == "volumes-enable") || *eventConsent != (mode == "events-enable") || flags.NArg() != 0 || mode == "" || *apply != mutate || (*consent || *windowsConsent) != needsConsent || *consent && *windowsConsent || *insecure && !*windowsConsent && !processMetricsMode && !networkMode && mode != "events-preview" && mode != "events-enable" && mode != "events-disable" && mode != "volumes-preview" && mode != "volumes-enable" && mode != "volumes-disable" || (mode == "install") != (*bootstrap != "") {
		fmt.Fprintln(stderr, "Operation flags rejected. Review --help; explicit apply and exactly one scope acknowledgement are required where stated.")
		return 2
	}
	if ctx == nil || perform == nil {
		reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonInvalidConfiguration, nil))
		return 1
	}
	profile := ""
	if *consent {
		profile = enrollmentcrypto.CollectionProfile
	}
	if *windowsConsent {
		profile = enrollmentcrypto.CollectionProfileWindowsInventory
		if _, err := fmt.Fprintln(out, enrollmentclient.WindowsInventoryPrivacy); err != nil {
			return 1
		}
	}
	if *networkConsent {
		if n, err := fmt.Fprintln(out, windowsnetwork.Privacy); err != nil || n != len(windowsnetwork.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowsnetwork.HTTPPrivacy); err != nil || n != len(windowsnetwork.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *processMetricsConsent {
		if _, err := fmt.Fprintln(out, windowsprocessmetrics.Privacy); err != nil {
			return 1
		}
		if *insecure {
			if _, err := fmt.Fprintln(out, windowsprocessmetrics.HTTPPrivacy); err != nil {
				return 1
			}
		}
	}
	if *volumeConsent {
		if _, err := fmt.Fprintln(out, windowsvolumes.Privacy); err != nil {
			return 1
		}
	}
	if *insecure && *volumeConsent {
		if _, err := fmt.Fprintln(out, windowsvolumes.HTTPPrivacy); err != nil {
			return 1
		}
	}
	if *eventConsent {
		if _, err := fmt.Fprintln(out, windowseventhealth.Privacy); err != nil {
			return 1
		}
	}
	if *insecure && *eventConsent {
		if _, err := fmt.Fprintln(out, windowseventhealth.HTTPPrivacy); err != nil {
			return 1
		}
	}
	if *insecure {
		if _, err := fmt.Fprintln(out, enrollmentclient.WindowsInventoryHTTPPrivacy); err != nil {
			return 1
		}
	}
	result, err := perform(ctx, request{mode: mode, bootstrap: *bootstrap, collectionProfile: profile, insecureHTTP: *insecure}, out, stderr)
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
	fmt.Fprintln(out, "Tracebolt Windows service source candidate (HTTPS by default). No Windows installation/reboot acceptance is established.")
	fmt.Fprintln(out, "Read only: --plan | --inspect")
	fmt.Fprintln(out, "Approved initial setup: --install --apply --basic-readonly --bootstrap-file ABSOLUTE_PROTECTED_PUBLIC_BOOTSTRAP")
	fmt.Fprintln(out, "Resume stopped enrollment: --enroll --apply --basic-readonly")
	fmt.Fprintln(out, "Fresh Windows inventory setup: replace --basic-readonly with --windows-inventory and use a matching windows-inventory-v1 bootstrap; both flags together are rejected.")
	fmt.Fprintln(out, "Disposable Windows inventory HTTP test only: additionally supply --insecure-http-test with a matching http-test bootstrap. Basic Windows remains TLS-only.")
	fmt.Fprintln(out, enrollmentclient.WindowsInventoryHTTPPrivacy)
	fmt.Fprintln(out, "Windows inventory scope: "+enrollmentclient.WindowsInventoryPrivacy)
	fmt.Fprintln(out, "Approved lifecycle: --start --apply | --stop --apply | --uninstall --apply")
	fmt.Fprintln(out, "Stopped installed inventory service: --events-preview | --events-enable --apply --application-system-event-headers | --events-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowseventhealth.Privacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --volumes-preview | --volumes-enable --apply --visible-volumes | --volumes-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsvolumes.Privacy)
	fmt.Fprintln(out, windowsvolumes.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --process-metrics-preview | --process-metrics-enable --apply --process-cpu-memory | --process-metrics-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsprocessmetrics.Privacy)
	fmt.Fprintln(out, windowsprocessmetrics.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --network-preview | --network-enable --apply --network-endpoints | --network-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsnetwork.Privacy)
	fmt.Fprintln(out, windowsnetwork.HTTPPrivacy)
	fmt.Fprintln(out, "SCM-only runtime: --run-service (rejects an ordinary console)")
	fmt.Fprintln(out, "Installation creates one LocalService SCM service, a scoped service SID and protected durable state, then asks for a hidden invitation and starts pending enrollment. Review these persistent changes and obtain action-time approval before applying. Public fingerprint/comparison approval in the manager remains mandatory.")
	fmt.Fprintln(out, "Basic scope: bounded OS, uptime, physical RAM and system-volume observation. No expanded hostname/IP/process/software/event content collection, Windows Update/CVE, remote commands or service-control requests from a manager. Production TLS is required; Linux managed profiles are rejected.")
	fmt.Fprintln(out, "Prerequisites: separately authorized provisioning of the fixed protected executable/parent directories, explicit LocalService read/execute access, and an administrator-only protected public bootstrap file. This candidate does not download/copy binaries, repair ACLs, enable privileges, adopt services or erase identities. Uninstall retains all private state.")
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// processMetricsOperation keeps local ownership/stopped verification ahead of
// every consent read or write. Tests inject both operations, never native APIs.
func processMetricsOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsProcessMetricsConsentResult, error),
) (lanclient.WindowsProcessMetricsConsentResult, error) {
	zero := lanclient.WindowsProcessMetricsConsentResult{}
	mode := map[string]string{"process-metrics-preview": "preview", "process-metrics-enable": "enable", "process-metrics-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}
