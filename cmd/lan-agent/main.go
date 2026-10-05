// lan-agent is a Linux read-only sender with optional foreground scheduling.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"localrmm/internal/agentloop"
	"localrmm/internal/journalhelper"
	"localrmm/internal/lanclient"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	if selected, exclusive := journalReaderInvocation(os.Args[1:]); selected {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		os.Exit(runJournalReader(ctx, exclusive, journalhelper.Run, os.Stderr))
	}

	path := flag.String("config", "", "Absolute protected preprovided agent configuration JSON")
	identity := flag.String("service-identity", "", "Expected numeric service UID:GID; rejects additional groups before state access")
	validate := flag.Bool("validate-guided", false, "Validate local guided handoff and existing ledger without collection or network")
	foreground := flag.Bool("foreground", false, "Repeat bounded read-only reports until interrupted; does not install a service")
	interval := flag.Duration("interval", 30*time.Second, "Foreground report interval, 15s to 1h")
	enrollmentBootstrap := flag.String("enrollment-bootstrap", "", "Fixed public bootstrap for explicit pending-service mode")
	enrollmentState := flag.String("enrollment-state-directory", "", "Existing private pending-service enrollment directory")
	insecurePending := flag.Bool("insecure-http-test", false, "Explicit unauthenticated HTTP pending-service acknowledgement")
	completeUpdatesConsentMode := flag.String("complete-cached-updates-consent", "", "Local-only preview, enable, or disable of all known cached APT candidate rows; stop the sender first")
	completeUpdatesConsentAck := flag.Bool("ack-complete-cached-updates", false, "Acknowledge transmitting all known cached APT candidate rows, installed/candidate versions, holds, unknown comparisons and original index age every six hours; no refresh/install/privilege change; HTTP-test is plaintext")
	cachedUpdatesConsentMode := flag.String("cached-updates-consent", "", "Local-only preview, enable, or disable of cached APT update status; stop the sender first")
	cachedUpdatesConsentAck := flag.Bool("ack-cached-updates", false, "Acknowledge package names/architectures/versions, cached APT candidates, dpkg holds, bounded sample/counts and index modification age; no refresh/install/privilege change; HTTP-test is plaintext")
	endpointConsentMode := flag.String("endpoint-identity-consent", "", "Local-only preview, enable, or disable of the explicit hostname/interface-address extension; stop the sender first")
	endpointConsentAck := flag.Bool("ack-endpoint-identity", false, "Acknowledge reporting hostname and all visible interface IPv4/IPv6 addresses to the configured manager")
	overviewConsentMode := flag.String("complete-overview-consent", "", "Local-only preview, enable, or disable of full visible processes/mounted filesystems; stop the sender first")
	overviewConsentAck := flag.Bool("ack-complete-overview", false, "Acknowledge full visible processes/mounts, potentially sensitive names, mount paths and filesystem labels in the agent Linux namespaces, at a fixed 60-second cadence; HTTP-test is unencrypted and unauthenticated")
	journalConsentMode := flag.String("journal-content-consent", "", "Local-only preview or create-only initialize of on-demand journal consent; stop the sender first")
	journalConsentAck := flag.Bool("ack-journal-content", false, "Acknowledge allowlisted service journal messages may contain credentials, personal data or other secrets")
	journalPlaintextAck := flag.Bool("ack-journal-http-plaintext", false, "Separately acknowledge unencrypted journal content visible on the LAN with an unauthenticated manager")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN agent requires --config PATH; no service installation is performed.")
		os.Exit(2)
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN sender state is currently supported on Linux only; native ACL validation is pending for other platforms.")
		os.Exit(2)
	}
	if *completeUpdatesConsentMode != "" || *completeUpdatesConsentAck {
		if *foreground || *validate || *interval != 30*time.Second || *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending || *cachedUpdatesConsentMode != "" || *cachedUpdatesConsentAck || *endpointConsentMode != "" || *endpointConsentAck || *overviewConsentMode != "" || *overviewConsentAck || *journalConsentMode != "" || *journalConsentAck || *journalPlaintextAck {
			fmt.Fprintln(os.Stderr, "Complete cached update consent cannot be combined with reporting, validation, enrollment or other consent modes.")
			os.Exit(2)
		}
		os.Exit(runCompleteUpdatesConsent(completeUpdatesConsentOptions{Path: *path, Mode: *completeUpdatesConsentMode, Identity: *identity, Acknowledged: *completeUpdatesConsentAck}, completeUpdatesConsentHooks{identity: serviceIdentity, configure: lanclient.ConfigureCompleteCachedUpdates}, os.Stdout, os.Stderr))
	}
	if *cachedUpdatesConsentMode != "" || *cachedUpdatesConsentAck {
		if *foreground || *validate || *interval != 30*time.Second || *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending || *endpointConsentMode != "" || *endpointConsentAck || *overviewConsentMode != "" || *overviewConsentAck || *journalConsentMode != "" || *journalConsentAck || *journalPlaintextAck {
			fmt.Fprintln(os.Stderr, "Cached update consent cannot be combined with reporting, validation, enrollment or other consent modes.")
			os.Exit(2)
		}
		os.Exit(runCachedUpdatesConsent(cachedUpdatesConsentOptions{Path: *path, Mode: *cachedUpdatesConsentMode, Identity: *identity, Acknowledged: *cachedUpdatesConsentAck}, cachedUpdatesConsentHooks{identity: serviceIdentity, configure: lanclient.ConfigureCachedUpdates}, os.Stdout, os.Stderr))
	}
	if *overviewConsentMode != "" || *overviewConsentAck {
		if *foreground || *validate || *interval != 30*time.Second || *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending || *endpointConsentMode != "" || *endpointConsentAck || *journalConsentMode != "" || *journalConsentAck || *journalPlaintextAck {
			fmt.Fprintln(os.Stderr, "Complete overview consent cannot be combined with reporting, validation, enrollment or other consent modes.")
			os.Exit(2)
		}
		os.Exit(runOverviewConsent(overviewConsentOptions{Path: *path, Mode: *overviewConsentMode, Identity: *identity, Acknowledged: *overviewConsentAck}, overviewConsentHooks{identity: serviceIdentity, configure: lanclient.ConfigureCompleteOverview}, os.Stdout, os.Stderr))
	}
	if *journalConsentMode != "" || *journalConsentAck || *journalPlaintextAck {
		if *foreground || *validate || *interval != 30*time.Second || *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending || *endpointConsentMode != "" || *endpointConsentAck {
			fmt.Fprintln(os.Stderr, "Journal consent mode cannot be combined with reporting, validation, pending enrollment or endpoint consent.")
			os.Exit(2)
		}
		os.Exit(runJournalConsent(journalConsentOptions{Path: *path, Mode: *journalConsentMode, Identity: *identity, Acknowledged: *journalConsentAck, Plaintext: *journalPlaintextAck}, journalConsentHooks{identity: serviceIdentity, configure: lanclient.ConfigureJournalContent}, os.Stdout, os.Stderr))
	}
	if *endpointConsentMode != "" || *endpointConsentAck {
		if *foreground || *validate || *interval != 30*time.Second || *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending {
			fmt.Fprintln(os.Stderr, "Endpoint consent mode cannot be combined with reporting, validation or pending-enrollment modes.")
			os.Exit(2)
		}
		os.Exit(runEndpointConsent(endpointConsentOptions{Path: *path, Mode: *endpointConsentMode, Identity: *identity, Acknowledged: *endpointConsentAck}, endpointConsentHooks{identity: serviceIdentity, configure: lanclient.ConfigureEndpointIdentity}, os.Stdout, os.Stderr))
	}
	if *identity != "" && (!*foreground || *validate || !serviceIdentity(*identity)) {
		fmt.Fprintln(os.Stderr, "Tracebolt service identity rejected before private-state access.")
		os.Exit(2)
	}
	if *validate {
		if *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending || *foreground || *interval != 30*time.Second || lanclient.ValidateGuidedHandoff(*path) != nil {
			fmt.Fprintln(os.Stderr, "Tracebolt guided handoff validation failed; identity and state preserved.")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "Tracebolt guided handoff validated locally; no collection or network request performed.")
		return
	}
	pendingMode := *enrollmentBootstrap != "" || *enrollmentState != "" || *insecurePending
	if pendingMode {
		if *enrollmentBootstrap == "" || *enrollmentState == "" || !*foreground || *validate || *identity == "" {
			fmt.Fprintln(os.Stderr, "Pending service requires the complete explicit bootstrap/state/identity contract.")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		os.Exit(runPendingService(ctx, pendingServiceOptions{BootstrapPath: *enrollmentBootstrap, StateDirectory: *enrollmentState, ConfigPath: *path, Identity: *identity, InsecureHTTPTest: *insecurePending, Interval: *interval}, os.Stdout, os.Stderr, defaultPendingServiceHooks()))
	}
	material, e := lanclient.Load(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Tracebolt agent configuration rejected.")
		os.Exit(2)
	}
	if material.Profile() == "http-test" {
		fmt.Fprintln(os.Stderr, "WARNING: UNENCRYPTED LAN TEST. Telemetry is visible and the manager is not authenticated. Use disposable test material.")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *foreground {
		encoder := json.NewEncoder(os.Stdout)
		_, e := lanclient.RunForeground(ctx, material, *interval, func(event agentloop.Event) error {
			return encoder.Encode(struct {
				SchemaVersion string          `json:"schemaVersion"`
				Event         agentloop.Event `json:"event"`
			}{"tracebolt.agent-loop.v1", event})
		})
		if e != nil && !errors.Is(e, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Tracebolt reporting stopped; inspect the safe status reason and local configuration.")
			os.Exit(1)
		}
		return
	}
	if *interval != 30*time.Second {
		fmt.Fprintln(os.Stderr, "--interval requires --foreground.")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	report, e := lanclient.Run(ctx, material)
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		os.Exit(2)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "Tracebolt delivery was not confirmed; inspect configuration/state and retry explicitly. No raw telemetry is printed.")
		os.Exit(1)
	}
}
