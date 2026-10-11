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
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventworker"
	"localrmm/internal/windowsupdateworker"
	"os"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowspatchworker"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecurityworker"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowssessionworker"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"path/filepath"
)

type request struct {
	mode, bootstrap, collectionProfile string
	insecureHTTP                       bool
}
type operation func(context.Context, request, io.Writer, io.Writer) (any, error)

func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	if len(args) == 1 && args[0] == windowseventworker.WorkerArgument {
		if runEventContentWorker(ctx, os.Stdin, out) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == windowsupdateworker.WorkerArgument {
		if runUpdatesWorker(ctx, os.Stdin, out) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == windowspatchworker.WorkerArgument {
		if runPatchContextWorker(ctx, os.Stdin, out) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == windowssessionworker.WorkerArgument || args[0] == windowssessionworker.JoinWorkerArgument) {
		if runSessionContextWorker(ctx, os.Stdin, out, args[0] == windowssessionworker.JoinWorkerArgument) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == windowssecurityworker.WorkerArgument || args[0] == windowssecurityworker.FirewallWorkerArgument) {
		if runSecurityPostureWorker(ctx, os.Stdin, out, args[0] == windowssecurityworker.FirewallWorkerArgument) != nil {
			return 1
		}
		return 0
	}
	return runWith(ctx, args, out, stderr, nativeOperation)
}
func runWith(ctx context.Context, args []string, out, stderr io.Writer, perform operation) int {
	flags := flag.NewFlagSet("windows-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	names := []string{"session-context-preview", "session-context-enable", "session-context-disable", "security-posture-preview", "security-posture-enable", "security-posture-disable", "patch-context-preview", "patch-context-enable", "patch-context-disable", "adapter-context-preview", "adapter-context-enable", "adapter-context-disable", "full-software-preview", "full-software-enable", "full-software-disable", "full-services-preview", "full-services-enable", "full-services-disable", "plan", "inspect", "install", "enroll", "start", "stop", "restart", "uninstall", "run-service", "events-preview", "events-enable", "events-disable", "volumes-preview", "volumes-enable", "volumes-disable", "process-metrics-preview", "process-metrics-enable", "process-metrics-disable", "network-preview", "network-enable", "network-disable", "service-startup-preview", "service-startup-enable", "service-startup-disable", "updates-preview", "updates-enable", "updates-disable", "event-content-preview", "event-content-enable", "event-content-disable"}
	modes := map[string]*bool{}
	for _, n := range names {
		modes[n] = flags.Bool(n, false, "")
	}
	apply := flags.Bool("apply", false, "")
	consent := flags.Bool("basic-readonly", false, "")
	eventContentConsent := flags.Bool("selected-application-system-event-messages", false, "")
	updatesConsent := flags.Bool("cached-windows-updates", false, "")
	fullSoftwareConsent := flags.Bool("complete-machine-software", false, "")
	fullServicesConsent := flags.Bool("complete-win32-services", false, "")
	serviceStartupConsent := flags.Bool("service-startup-metadata", false, "")
	sessionContextConsent := flags.Bool("user-session-join-metadata", false, "")
	securityPostureConsent := flags.Bool("defender-firewall-posture", false, "")
	patchContextConsent := flags.Bool("windows-build-history-reboot", false, "")
	adapterContextConsent := flags.Bool("adapter-link-dns-gateways", false, "")
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
	fullSoftwareMode := mode == "full-software-preview" || mode == "full-software-enable" || mode == "full-software-disable"
	fullServicesMode := mode == "full-services-preview" || mode == "full-services-enable" || mode == "full-services-disable"
	eventContentMode := mode == "event-content-preview" || mode == "event-content-enable" || mode == "event-content-disable"
	updatesMode := mode == "updates-preview" || mode == "updates-enable" || mode == "updates-disable"
	serviceStartupMode := mode == "service-startup-preview" || mode == "service-startup-enable" || mode == "service-startup-disable"
	sessionContextMode := mode == "session-context-preview" || mode == "session-context-enable" || mode == "session-context-disable"
	securityPostureMode := mode == "security-posture-preview" || mode == "security-posture-enable" || mode == "security-posture-disable"
	patchContextMode := mode == "patch-context-preview" || mode == "patch-context-enable" || mode == "patch-context-disable"
	adapterContextMode := mode == "adapter-context-preview" || mode == "adapter-context-enable" || mode == "adapter-context-disable"
	networkMode := mode == "network-preview" || mode == "network-enable" || mode == "network-disable"
	processMetricsMode := mode == "process-metrics-preview" || mode == "process-metrics-enable" || mode == "process-metrics-disable"
	mutate := mode == "session-context-enable" || mode == "session-context-disable" || mode == "security-posture-enable" || mode == "security-posture-disable" || mode == "patch-context-enable" || mode == "patch-context-disable" || mode == "adapter-context-enable" || mode == "adapter-context-disable" || mode == "full-software-enable" || mode == "full-software-disable" || mode == "full-services-enable" || mode == "full-services-disable" || mode == "event-content-enable" || mode == "event-content-disable" || mode == "updates-enable" || mode == "updates-disable" || mode == "service-startup-enable" || mode == "service-startup-disable" || mode == "network-enable" || mode == "network-disable" || mode == "process-metrics-enable" || mode == "process-metrics-disable" || mode == "install" || mode == "enroll" || mode == "start" || mode == "stop" || mode == "restart" || mode == "uninstall" || mode == "events-enable" || mode == "events-disable" || mode == "volumes-enable" || mode == "volumes-disable"
	needsConsent := mode == "install" || mode == "enroll"
	if *sessionContextConsent != (mode == "session-context-enable") || *securityPostureConsent != (mode == "security-posture-enable") || *patchContextConsent != (mode == "patch-context-enable") || *adapterContextConsent != (mode == "adapter-context-enable") || *fullSoftwareConsent != (mode == "full-software-enable") || *fullServicesConsent != (mode == "full-services-enable") || *eventContentConsent != (mode == "event-content-enable") || *updatesConsent != (mode == "updates-enable") || *serviceStartupConsent != (mode == "service-startup-enable") || *networkConsent != (mode == "network-enable") || *processMetricsConsent != (mode == "process-metrics-enable") || *volumeConsent != (mode == "volumes-enable") || *eventConsent != (mode == "events-enable") || flags.NArg() != 0 || mode == "" || *apply != mutate || (*consent || *windowsConsent) != needsConsent || *consent && *windowsConsent || *insecure && !*windowsConsent && !processMetricsMode && !networkMode && !patchContextMode && !securityPostureMode && !sessionContextMode && !adapterContextMode && !serviceStartupMode && !updatesMode && !eventContentMode && !fullServicesMode && !fullSoftwareMode && mode != "events-preview" && mode != "events-enable" && mode != "events-disable" && mode != "volumes-preview" && mode != "volumes-enable" && mode != "volumes-disable" || (mode == "install") != (*bootstrap != "") {
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
	if *fullServicesConsent || mode == "full-services-preview" {
		if n, e := fmt.Fprintln(out, windowsfullservices.Privacy); e != nil || n != len(windowsfullservices.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsfullservices.HTTPPrivacy); e != nil || n != len(windowsfullservices.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *fullSoftwareConsent || mode == "full-software-preview" {
		if n, e := fmt.Fprintln(out, windowsfullsoftware.Privacy); e != nil || n != len(windowsfullsoftware.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsfullsoftware.HTTPPrivacy); e != nil || n != len(windowsfullsoftware.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *eventContentConsent || mode == "event-content-preview" {
		if n, err := fmt.Fprintln(out, windowseventrequest.Privacy); err != nil || n != len(windowseventrequest.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowseventrequest.HTTPPrivacy); err != nil || n != len(windowseventrequest.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *updatesConsent || mode == "updates-preview" {
		if n, err := fmt.Fprintln(out, windowsupdates.Privacy); err != nil || n != len(windowsupdates.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowsupdates.HTTPPrivacy); err != nil || n != len(windowsupdates.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *serviceStartupConsent {
		if n, err := fmt.Fprintln(out, windowsmanaged.ServiceStartupPrivacy); err != nil || n != len(windowsmanaged.ServiceStartupPrivacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowsmanaged.ServiceStartupHTTPPrivacy); err != nil || n != len(windowsmanaged.ServiceStartupHTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *patchContextConsent || mode == "patch-context-preview" {
		if n, err := fmt.Fprintln(out, windowspatchcontext.Privacy); err != nil || n != len(windowspatchcontext.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowspatchcontext.HTTPPrivacy); err != nil || n != len(windowspatchcontext.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *sessionContextConsent || mode == "session-context-preview" {
		if n, err := fmt.Fprintln(out, windowssessions.Privacy); err != nil || n != len(windowssessions.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowssessions.HTTPPrivacy); err != nil || n != len(windowssessions.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *securityPostureConsent || mode == "security-posture-preview" {
		if n, err := fmt.Fprintln(out, windowssecurity.Privacy); err != nil || n != len(windowssecurity.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowssecurity.HTTPPrivacy); err != nil || n != len(windowssecurity.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *adapterContextConsent {
		if n, err := fmt.Fprintln(out, windowsadapters.Privacy); err != nil || n != len(windowsadapters.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowsadapters.HTTPPrivacy); err != nil || n != len(windowsadapters.HTTPPrivacy)+1 {
				return 1
			}
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
	// The public restart budget starts before layout/receipt/lease acquisition,
	// not only when the SCM engine is entered. Native calls remain synchronous.
	if mode == "restart" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, windowsservice.RestartTimeout)
		defer cancel()
	}
	result, err := perform(ctx, request{mode: mode, bootstrap: *bootstrap, collectionProfile: profile, insecureHTTP: *insecure}, out, stderr)
	if err != nil {
		// Only the finite own-agent restart result is emitted on failure. Other
		// operation result semantics remain unchanged; no raw error is encoded.
		if mode == "restart" {
			partial, ok := result.(windowsservice.RestartResult)
			if !ok {
				partial = windowsservice.RestartResult{Outcome: "not-requested", Phase: "receipt", StateRetained: true}
			}
			if writeErr := writeLifecycleResult(out, partial); writeErr != nil {
				reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonResultWrite, writeErr))
			}
		}
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
func writeLifecycleResult(out io.Writer, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errLifecycle
	}
	data = append(data, '\n')
	n, err := out.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Complete caller-visible Win32 services, separately consented with the owned service stopped: --full-services-preview; --full-services-enable --apply --complete-win32-services; --full-services-disable --apply. HTTP-test also requires --insecure-http-test. No old grant authorizes this scope.")
	fmt.Fprintln(out, "Complete caller-visible HKLM 32/64 machine software registrations, separately consented with the owned service stopped: --full-software-preview; --full-software-enable --apply --complete-machine-software; --full-software-disable --apply. HTTP-test also requires --insecure-http-test. Per-user, Store and portable programs are excluded; no old grant authorizes this scope.")
	fmt.Fprintln(out, windowsfullservices.Privacy)
	fmt.Fprintln(out, windowsfullservices.HTTPPrivacy)
	fmt.Fprintln(out, "Tracebolt Windows service source candidate (HTTPS by default). No Windows installation/reboot acceptance is established.")
	fmt.Fprintln(out, "Read only: --plan | --inspect")
	fmt.Fprintln(out, "Approved initial setup: --install --apply --basic-readonly --bootstrap-file ABSOLUTE_PROTECTED_PUBLIC_BOOTSTRAP")
	fmt.Fprintln(out, "Resume stopped enrollment: --enroll --apply --basic-readonly")
	fmt.Fprintln(out, "Fresh Windows inventory setup: replace --basic-readonly with --windows-inventory and use a matching windows-inventory-v1 bootstrap; both flags together are rejected.")
	fmt.Fprintln(out, "Disposable Windows inventory HTTP test only: additionally supply --insecure-http-test with a matching http-test bootstrap. Basic Windows remains TLS-only.")
	fmt.Fprintln(out, enrollmentclient.WindowsInventoryHTTPPrivacy)
	fmt.Fprintln(out, "Windows inventory scope: "+enrollmentclient.WindowsInventoryPrivacy)
	fmt.Fprintln(out, "Restart is local own-agent lifecycle only: requires a running receipt-owned service, attempts stop/start once, and observes SCM within a cooperative 45-second budget. Initially stopped/pending services are rejected. Native calls can outlast the budget; unknown outcomes need inspection, never automatic retry. No health/reporting/reboot proof or remote other-service authority.")
	fmt.Fprintln(out, "Approved lifecycle: --start --apply | --stop --apply | --restart --apply | --uninstall --apply")
	fmt.Fprintln(out, "Stopped installed inventory service: --events-preview | --events-enable --apply --application-system-event-headers | --events-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowseventhealth.Privacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --volumes-preview | --volumes-enable --apply --visible-volumes | --volumes-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsvolumes.Privacy)
	fmt.Fprintln(out, windowsvolumes.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --process-metrics-preview | --process-metrics-enable --apply --process-cpu-memory | --process-metrics-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsprocessmetrics.Privacy)
	fmt.Fprintln(out, windowsprocessmetrics.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --network-preview | --network-enable --apply --network-endpoints | --network-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, "Stopped owned inventory service: --session-context-preview | --session-context-enable --apply --user-session-join-metadata | --session-context-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart.")
	fmt.Fprintln(out, "Stopped owned inventory service: --security-posture-preview | --security-posture-enable --apply --defender-firewall-posture | --security-posture-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart.")
	fmt.Fprintln(out, "Stopped owned inventory service: --patch-context-preview | --patch-context-enable --apply --windows-build-history-reboot | --patch-context-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart.")
	fmt.Fprintln(out, "Stopped owned inventory service: --adapter-context-preview | --adapter-context-enable --apply --adapter-link-dns-gateways | --adapter-context-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart.")
	fmt.Fprintln(out, windowsadapters.Privacy)
	fmt.Fprintln(out, windowsadapters.HTTPPrivacy)
	fmt.Fprintln(out, windowsnetwork.Privacy)
	fmt.Fprintln(out, windowsnetwork.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --service-startup-preview | --service-startup-enable --apply --service-startup-metadata | --service-startup-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsmanaged.ServiceStartupPrivacy)
	fmt.Fprintln(out, windowsmanaged.ServiceStartupHTTPPrivacy)
	fmt.Fprintln(out, "Stopped owned inventory service, separate selected message-content scope: --event-content-preview | --event-content-enable --apply --selected-application-system-event-messages | --event-content-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowseventrequest.Privacy)
	fmt.Fprintln(out, windowseventrequest.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped owned inventory service, separate cached Windows Update scope: --updates-preview | --updates-enable --apply --cached-windows-updates | --updates-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsupdates.Privacy)
	fmt.Fprintln(out, windowsupdates.HTTPPrivacy)
	fmt.Fprintln(out, "SCM-only runtime: --run-service (rejects an ordinary console)")
	fmt.Fprintln(out, "Installation creates one LocalService SCM service, a scoped service SID and protected durable state, then asks for a hidden invitation and starts pending enrollment. Review these persistent changes and obtain action-time approval before applying. Public fingerprint/comparison approval in the manager remains mandatory.")
	fmt.Fprintln(out, "Basic scope: bounded OS, uptime, physical RAM and system-volume observation. No expanded hostname/IP/process/software/event content collection, Windows Update/CVE, remote commands or service-control requests from a manager. Production TLS is required; Linux managed profiles are rejected.")
	fmt.Fprintln(out, "Prerequisites: separately authorized provisioning of the fixed protected executable/parent directories, explicit LocalService read/execute access, and an administrator-only protected public bootstrap file. This candidate does not download/copy binaries, repair ACLs, enable privileges, adopt services or erase identities. Uninstall retains all private state.")
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
