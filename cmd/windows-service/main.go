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
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistoryworker"
	"localrmm/internal/windowsupdateworker"
	"os"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshardwareworker"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowspatchworker"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourceworker"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverageworker"
	"localrmm/internal/windowssecurityworker"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowssessionworker"
	"localrmm/internal/windowsstorageioworker"
	"localrmm/internal/windowsstorageworker"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsusersoftware"
	"localrmm/internal/windowsvolumes"
	"path/filepath"
)

type request struct {
	mode, bootstrap, collectionProfile string
	insecureHTTP                       bool
	automaticRenewal                   bool
}
type operation func(context.Context, request, io.Writer, io.Writer) (any, error)

func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--background-updates-activate" {
		return runBackgroundUpdateActivate(ctx, args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "--coordinated-mutations-provision" {
		return runCoordinatedMutationProvision(ctx, args[1:], out, stderr, nativeCoordinatedMutationProvision)
	}
	if len(args) > 0 && args[0] == "--managed-msi-export" {
		return runManagedMSIExport(ctx, args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "--managed-msi-provision" {
		return runManagedMSIProvision(ctx, args[1:], out, stderr, nativeManagedMSIProvision)
	}
	if len(args) > 0 && args[0] == "--managed-msi-activate" {
		return runManagedMSIActivate(ctx, args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "--selected-updates-export" {
		return runUpdateExport(ctx, args[1:], out, stderr, nativeUpdateExport)
	}
	if len(args) > 0 && args[0] == "--prepared-msi-provision" {
		return runSoftwareProvision(ctx, args[1:], out, stderr, nativeSoftwareProvision)
	}
	if len(args) > 0 && args[0] == "--prepared-msi-export" {
		return runSoftwareExport(ctx, args[1:], out, stderr, nativeSoftwareExport)
	}
	if len(args) > 0 && args[0] == "--selected-updates-provision" {
		return runUpdateProvision(ctx, args[1:], out, stderr, nativeUpdateProvision)
	}
	if len(args) > 0 && args[0] == "--selected-updates-remove" {
		return runUpdateRemove(ctx, args[1:], out, stderr, nativeUpdateRemove)
	}
	if len(args) > 0 && args[0] == "--service-actions-provision" {
		return runActionProvision(ctx, args[1:], out, stderr, nativeActionProvision)
	}
	if len(args) > 0 && args[0] == "--service-actions-setup" {
		return runActionSetup(ctx, args[1:], out, stderr, nativeActionSetup)
	}
	if len(args) == 1 && args[0] == windowshistoryworker.WorkerArgument {
		if runEventHistoryWorker(ctx, os.Stdin, out) != nil {
			return 1
		}
		return 0
	}
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
	if len(args) == 1 && args[0] == windowsstorageioworker.WorkerArgument {
		if runStorageIOWorker(ctx, os.Stdin, out) != nil {
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
	if len(args) == 1 && (args[0] == windowsstorageworker.WorkerArgument || args[0] == windowsstorageworker.DisksWorkerArgument) {
		source := "drives"
		if args[0] == windowsstorageworker.DisksWorkerArgument {
			source = "disks"
		}
		if runStorageContextWorker(ctx, os.Stdin, out, source) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == windowssecuritycoverageworker.WorkerArgument || args[0] == windowssecuritycoverageworker.TPMWorkerArgument) {
		source := "antivirus"
		if args[0] == windowssecuritycoverageworker.TPMWorkerArgument {
			source = "tpm"
		}
		if runSecurityCoverageWorker(ctx, os.Stdin, out, source) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 {
		source := ""
		switch args[0] {
		case windowshardwareworker.WorkerArgument:
			source = "system"
		case windowshardwareworker.FirmwareWorkerArgument:
			source = "firmware"
		case windowshardwareworker.ChassisWorkerArgument:
			source = "chassis"
		case windowshardwareworker.PowerWorkerArgument:
			source = "power"
		}
		if source != "" {
			if runHardwareContextWorker(ctx, os.Stdin, out, source) != nil {
				return 1
			}
			return 0
		}
	}
	if len(args) == 1 {
		source := ""
		switch args[0] {
		case windowsresourceworker.WorkerArgument:
			source = "processors"
		case windowsresourceworker.InstalledMemoryWorkerArgument:
			source = "installed-memory"
		case windowsresourceworker.MemoryWorkerArgument:
			source = "memory"
		case windowsresourceworker.PagefilesWorkerArgument:
			source = "pagefiles"
		}
		if source != "" {
			if runResourceContextWorker(ctx, os.Stdin, out, source) != nil {
				return 1
			}
			return 0
		}
	}
	return runWith(ctx, args, out, stderr, nativeOperation)
}
func runWith(ctx context.Context, args []string, out, stderr io.Writer, perform operation) int {
	flags := flag.NewFlagSet("windows-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	names := []string{"user-software-preview", "user-software-enable", "user-software-disable", "software-history-preview", "software-history-enable", "software-history-disable", "network-context-preview", "network-context-enable", "network-context-disable", "full-processes-preview", "full-processes-enable", "full-processes-disable", "read-admin-preview", "read-admin-enable", "session-context-preview", "session-context-enable", "session-context-disable", "security-posture-preview", "security-posture-enable", "security-posture-disable", "patch-context-preview", "patch-context-enable", "patch-context-disable", "adapter-context-preview", "adapter-context-enable", "adapter-context-disable", "full-software-preview", "full-software-enable", "full-software-disable", "full-services-preview", "full-services-enable", "full-services-disable", "plan", "inspect", "install", "enroll", "start", "stop", "restart", "uninstall", "run-service", "events-preview", "events-enable", "events-disable", "volumes-preview", "volumes-enable", "volumes-disable", "process-metrics-preview", "process-metrics-enable", "process-metrics-disable", "network-preview", "network-enable", "network-disable", "service-startup-preview", "service-startup-enable", "service-startup-disable", "updates-preview", "updates-enable", "updates-disable", "event-content-preview", "event-content-enable", "event-content-disable", "event-history-preview", "event-history-enable", "event-history-disable"}
	modes := map[string]*bool{}
	for _, n := range names {
		modes[n] = flags.Bool(n, false, "")
	}
	apply := flags.Bool("apply", false, "")
	readAdminConsent := flags.Bool("twelve-read-admin-scopes", false, "")
	consent := flags.Bool("basic-readonly", false, "")
	eventHistoryConsent := flags.Bool("application-system-event-history-and-messages", false, "")
	eventContentConsent := flags.Bool("selected-application-system-event-messages", false, "")
	updatesConsent := flags.Bool("cached-windows-updates", false, "")
	networkContextConsent := flags.Bool("routes-interface-counters", false, "")
	fullProcessesConsent := flags.Bool("complete-process-inventory", false, "")
	userSoftwareConsent := flags.Bool("selected-user-software", false, "")
	softwareHistoryConsent := flags.Bool("machine-software-history", false, "")
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
	automaticRenewal := flags.Bool("automatic-certificate-renewal", false, enrollmentclient.AutomaticRenewalPrivacy)
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
	if *automaticRenewal && ((mode != "install" && mode != "enroll") || *insecure) {
		fmt.Fprintln(stderr, "Automatic certificate renewal requires a fresh HTTPS enrollment and exact renewable bootstrap.")
		return 2
	}
	readAdminMode := mode == "read-admin-preview" || mode == "read-admin-enable"
	networkContextMode := mode == "network-context-preview" || mode == "network-context-enable" || mode == "network-context-disable"
	fullProcessesMode := mode == "full-processes-preview" || mode == "full-processes-enable" || mode == "full-processes-disable"
	userSoftwareMode := mode == "user-software-preview" || mode == "user-software-enable" || mode == "user-software-disable"
	softwareHistoryMode := mode == "software-history-preview" || mode == "software-history-enable" || mode == "software-history-disable"
	fullSoftwareMode := mode == "full-software-preview" || mode == "full-software-enable" || mode == "full-software-disable"
	fullServicesMode := mode == "full-services-preview" || mode == "full-services-enable" || mode == "full-services-disable"
	eventHistoryMode := mode == "event-history-preview" || mode == "event-history-enable" || mode == "event-history-disable"
	eventContentMode := mode == "event-content-preview" || mode == "event-content-enable" || mode == "event-content-disable"
	updatesMode := mode == "updates-preview" || mode == "updates-enable" || mode == "updates-disable"
	serviceStartupMode := mode == "service-startup-preview" || mode == "service-startup-enable" || mode == "service-startup-disable"
	sessionContextMode := mode == "session-context-preview" || mode == "session-context-enable" || mode == "session-context-disable"
	securityPostureMode := mode == "security-posture-preview" || mode == "security-posture-enable" || mode == "security-posture-disable"
	patchContextMode := mode == "patch-context-preview" || mode == "patch-context-enable" || mode == "patch-context-disable"
	adapterContextMode := mode == "adapter-context-preview" || mode == "adapter-context-enable" || mode == "adapter-context-disable"
	networkMode := mode == "network-preview" || mode == "network-enable" || mode == "network-disable"
	processMetricsMode := mode == "process-metrics-preview" || mode == "process-metrics-enable" || mode == "process-metrics-disable"
	mutate := mode == "user-software-enable" || mode == "user-software-disable" || mode == "event-history-enable" || mode == "event-history-disable" || mode == "software-history-enable" || mode == "software-history-disable" || mode == "network-context-enable" || mode == "network-context-disable" || mode == "full-processes-enable" || mode == "full-processes-disable" || mode == "read-admin-enable" || mode == "session-context-enable" || mode == "session-context-disable" || mode == "security-posture-enable" || mode == "security-posture-disable" || mode == "patch-context-enable" || mode == "patch-context-disable" || mode == "adapter-context-enable" || mode == "adapter-context-disable" || mode == "full-software-enable" || mode == "full-software-disable" || mode == "full-services-enable" || mode == "full-services-disable" || mode == "event-content-enable" || mode == "event-content-disable" || mode == "updates-enable" || mode == "updates-disable" || mode == "service-startup-enable" || mode == "service-startup-disable" || mode == "network-enable" || mode == "network-disable" || mode == "process-metrics-enable" || mode == "process-metrics-disable" || mode == "install" || mode == "enroll" || mode == "start" || mode == "stop" || mode == "restart" || mode == "uninstall" || mode == "events-enable" || mode == "events-disable" || mode == "volumes-enable" || mode == "volumes-disable"
	needsConsent := mode == "install" || mode == "enroll"
	if *userSoftwareConsent != (mode == "user-software-enable") || *eventHistoryConsent != (mode == "event-history-enable") || *softwareHistoryConsent != (mode == "software-history-enable") || *networkContextConsent != (mode == "network-context-enable") || *fullProcessesConsent != (mode == "full-processes-enable") || *readAdminConsent != (mode == "read-admin-enable") || *sessionContextConsent != (mode == "session-context-enable") || *securityPostureConsent != (mode == "security-posture-enable") || *patchContextConsent != (mode == "patch-context-enable") || *adapterContextConsent != (mode == "adapter-context-enable") || *fullSoftwareConsent != (mode == "full-software-enable") || *fullServicesConsent != (mode == "full-services-enable") || *eventContentConsent != (mode == "event-content-enable") || *updatesConsent != (mode == "updates-enable") || *serviceStartupConsent != (mode == "service-startup-enable") || *networkConsent != (mode == "network-enable") || *processMetricsConsent != (mode == "process-metrics-enable") || *volumeConsent != (mode == "volumes-enable") || *eventConsent != (mode == "events-enable") || flags.NArg() != 0 || mode == "" || *apply != mutate || (*consent || *windowsConsent) != needsConsent || *consent && *windowsConsent || *insecure && !*windowsConsent && !readAdminMode && !processMetricsMode && !networkMode && !patchContextMode && !securityPostureMode && !sessionContextMode && !adapterContextMode && !serviceStartupMode && !updatesMode && !eventContentMode && !eventHistoryMode && !fullServicesMode && !fullSoftwareMode && !softwareHistoryMode && !userSoftwareMode && !fullProcessesMode && !networkContextMode && mode != "events-preview" && mode != "events-enable" && mode != "events-disable" && mode != "volumes-preview" && mode != "volumes-enable" && mode != "volumes-disable" || (mode == "install") != (*bootstrap != "") {
		fmt.Fprintln(stderr, "Operation flags rejected. Review --help; explicit apply and exactly one scope acknowledgement are required where stated.")
		return 2
	}
	if ctx == nil || perform == nil {
		reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonInvalidConfiguration, nil))
		return 1
	}
	if *automaticRenewal {
		if n, err := fmt.Fprintln(out, enrollmentclient.AutomaticRenewalPrivacy); err != nil || n != len(enrollmentclient.AutomaticRenewalPrivacy)+1 {
			return 1
		}
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
	if readAdminMode {
		if e := writeReadSetupDisclosure(out, readAdminSetupConsent(*insecure)); e != nil {
			return 1
		}
		text := "Read admin uses the same limited LocalService identity. Provider presence is not checked; service-token access remains unverified. Selected event-message content, cached WUA inspection and service control are separate. Existing-agent setup requires a compatible receipt-bound binary and a stopped owned service; no binary upgrade, Start or privilege change is performed.\n"
		if n, e := io.WriteString(out, text); e != nil || n != len(text) {
			return 1
		}
	}
	if *userSoftwareConsent || mode == "user-software-preview" {
		if n, e := fmt.Fprintln(out, windowsusersoftware.Privacy); e != nil || n != len(windowsusersoftware.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsusersoftware.HTTPPrivacy); e != nil || n != len(windowsusersoftware.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *softwareHistoryConsent || mode == "software-history-preview" {
		if n, e := fmt.Fprintln(out, windowsfullsoftware.HistoryPrivacy); e != nil || n != len(windowsfullsoftware.HistoryPrivacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsfullsoftware.HistoryHTTPPrivacy); e != nil || n != len(windowsfullsoftware.HistoryHTTPPrivacy)+1 {
				return 1
			}
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
	if *fullProcessesConsent || mode == "full-processes-preview" {
		if n, e := fmt.Fprintln(out, windowsfullprocesses.Privacy); e != nil || n != len(windowsfullprocesses.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsfullprocesses.HTTPPrivacy); e != nil || n != len(windowsfullprocesses.HTTPPrivacy)+1 {
				return 1
			}
		}
	}
	if *networkContextConsent || mode == "network-context-preview" {
		if n, e := fmt.Fprintln(out, windowsnetworkcontext.Privacy); e != nil || n != len(windowsnetworkcontext.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, e := fmt.Fprintln(out, windowsnetworkcontext.HTTPPrivacy); e != nil || n != len(windowsnetworkcontext.HTTPPrivacy)+1 {
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
	if *eventHistoryConsent || mode == "event-history-preview" {
		if n, err := fmt.Fprintln(out, windowshistoryrequest.Privacy); err != nil || n != len(windowshistoryrequest.Privacy)+1 {
			return 1
		}
		if *insecure {
			if n, err := fmt.Fprintln(out, windowshistoryrequest.HTTPPrivacy); err != nil || n != len(windowshistoryrequest.HTTPPrivacy)+1 {
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
	result, err := perform(ctx, request{automaticRenewal: *automaticRenewal, mode: mode, bootstrap: *bootstrap, collectionProfile: profile, insecureHTTP: *insecure}, out, stderr)
	if err != nil {
		if readAdminMode {
			if partial, ok := result.(readAdminReconsentResult); ok {
				if partial.Status == "configured-service-remains-stopped" {
					partial.Status = "receipt-release-unverified"
				}
				if e := writeLifecycleResult(out, partial); e != nil {
					reportDiagnostic(stderr, marked(windowsservice.PhaseLifecycle, windowsservice.ReasonResultWrite, e))
				}
			}
		}
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
	fmt.Fprintln(out, "Separate selected service control provisioning: --service-actions-provision --policy-file <reviewed policy> --broker-file <matching broker.exe> --artifact-manifest <public manifest>. Read-only plan first; --apply --approve <exact plan digest> --acknowledge-service-control is separate local consent. Broker remains disabled and observer stopped. No target action.")
	fmt.Fprintln(out, "Fresh HTTPS renewable bootstrap only: add --automatic-certificate-renewal. "+enrollmentclient.AutomaticRenewalPrivacy)
	fmt.Fprintln(out, "One-time existing-agent read-admin consent: --read-admin-preview; --read-admin-enable --apply --twelve-read-admin-scopes. Compatible receipt-owned installed binary and stopped activated inventory service required. HTTP-test also requires --insecure-http-test. No binary upgrade, repair, service start, service control, event-message content or cached WUA inspection is included.")
	fmt.Fprintln(out, "Complete caller-visible Win32 services, separately consented with the owned service stopped: --full-services-preview; --full-services-enable --apply --complete-win32-services; --full-services-disable --apply. HTTP-test also requires --insecure-http-test. No old grant authorizes this scope.")
	fmt.Fprintln(out, "Local route and interface-counter metadata, separately consented with the owned service stopped: --network-context-preview; --network-context-enable --apply --routes-interface-counters; --network-context-disable --apply. HTTP-test also requires --insecure-http-test. Includes route prefix/next-hop/index/metric/protocol/origin, interface aliases and exact raw uint64 octet/error/discard counters. No joins, rates, since-boot claims, MACs, GUIDs, packets, probes, DNS, remote reads or grants.")
	fmt.Fprintln(out, "Complete caller-visible Toolhelp process snapshot, separately consented with the owned service stopped: --full-processes-preview; --full-processes-enable --apply --complete-process-inventory; --full-processes-disable --apply. HTTP-test also requires --insecure-http-test. Includes PID, parent PID, executable name availability and thread count; excludes process handles, owners, paths, commands, filesystem, CPU and RAM. Existing bounded process metrics remain separately consented.")
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
	fmt.Fprintln(out, "Stopped owned inventory service, separate foreground receive scope: --user-software-preview | --user-software-enable --apply --selected-user-software | --user-software-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart or user-context read. After separately authorized startup, run the matching tracebolt-windows-user-software-amd64.exe or tracebolt-windows-user-software-arm64.exe in the selected normal user's own interactive session and explicitly approve each capture.")
	fmt.Fprintln(out, windowsusersoftware.Privacy)
	fmt.Fprintln(out, windowsusersoftware.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped owned inventory service with software already enabled: --software-history-preview | --software-history-enable --apply --machine-software-history | --software-history-disable --apply. HTTP-test also requires --insecure-http-test. Separate default-off history approval; no automatic restart.")
	fmt.Fprintln(out, windowsfullsoftware.HistoryPrivacy)
	fmt.Fprintln(out, windowsfullsoftware.HistoryHTTPPrivacy)
	fmt.Fprintln(out, "Stopped owned inventory service: --adapter-context-preview | --adapter-context-enable --apply --adapter-link-dns-gateways | --adapter-context-disable --apply. HTTP-test also requires --insecure-http-test. No automatic restart.")
	fmt.Fprintln(out, windowsadapters.Privacy)
	fmt.Fprintln(out, windowsadapters.HTTPPrivacy)
	fmt.Fprintln(out, windowsnetwork.Privacy)
	fmt.Fprintln(out, windowsnetwork.HTTPPrivacy)
	fmt.Fprintln(out, "Stopped installed inventory service: --service-startup-preview | --service-startup-enable --apply --service-startup-metadata | --service-startup-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowsmanaged.ServiceStartupPrivacy)
	fmt.Fprintln(out, windowsmanaged.ServiceStartupHTTPPrivacy)
	fmt.Fprintln(out, "Stopped owned inventory service, separate selected message-content scope: --event-content-preview | --event-content-enable --apply --selected-application-system-event-messages | --event-content-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, "Stopped owned inventory service, separate history and selected historical message scope: --event-history-preview | --event-history-enable --apply --application-system-event-history-and-messages | --event-history-disable --apply. HTTP-test additionally requires --insecure-http-test. No automatic service restart.")
	fmt.Fprintln(out, windowshistoryrequest.Privacy)
	fmt.Fprintln(out, windowshistoryrequest.HTTPPrivacy)
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
