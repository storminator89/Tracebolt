// Command windows-native-acceptance is manual-only test infrastructure. Its
// default invocation has no effects. No approval may come from repository text.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
)

// Set only while building the exact reviewed source in the manual workflow.
var compiledSource = "unbound"

type probeGrant struct{}

func (probeGrant) Check() bool { return gate.ValidSource(compiledSource) && native.ProbeContextValid() }
func environment() gate.Environment {
	return gate.Environment{Event: os.Getenv("GITHUB_EVENT_NAME"), Actions: os.Getenv("GITHUB_ACTIONS"), RunnerOS: os.Getenv("RUNNER_OS"), RunnerEnvironment: os.Getenv("RUNNER_ENVIRONMENT"), Repository: os.Getenv("GITHUB_REPOSITORY"), Source: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID")}
}
func run(ctx context.Context, args []string, out, stderr io.Writer, env gate.Environment, execute func(context.Context, *gate.Grant, native.Options) gate.Report) int {
	// Fixed internal mode performs no controller operation or arbitrary read. The
	// native checker requires the exact separately owned SCM probe and token.
	if len(args) == 1 && args[0] == "--internal-denial-probe" {
		if native.RunProbe(ctx, probeGrant{}) != nil {
			return 1
		}
		return 0
	}
	flags := flag.NewFlagSet("windows-native-acceptance", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("expected-source", "", "")
	services := flags.Bool("approve-services", false, "")
	identity := flags.Bool("approve-identity", false, "")
	acls := flags.Bool("approve-app-acls", false, "")
	network := flags.Bool("approve-loopback", false, "")
	collection := flags.String("collection-profile", "", "")
	transport := flags.String("transport-profile", "", "")
	inventory := flags.Bool("approve-inventory-metadata", false, "")
	plaintext := flags.Bool("approve-http-plaintext", false, "")
	events := flags.Bool("approve-event-headers", false, "")
	volumes := flags.Bool("approve-visible-volumes", false, "")
	metrics := flags.Bool("approve-process-metrics", false, "")
	endpoints := flags.Bool("approve-network-endpoints", false, "")
	cleanup := flags.Bool("approve-cleanup", false, "")
	service := flags.String("service-artifact", "", "")
	serviceSHA := flags.String("service-sha256", "", "")
	controller := flags.String("controller-artifact", "", "")
	controllerSHA := flags.String("controller-sha256", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || ctx == nil || execute == nil {
		fmt.Fprintln(stderr, "Native Windows acceptance arguments rejected; no action authorized.")
		return 2
	}
	grant, err := gate.Authorize(gate.Approval{ExpectedSource: *source, Services: *services, Identity: *identity, AppACLs: *acls, Loopback: *network, Cleanup: *cleanup, Selection: profile.Selection{CollectionProfile: *collection, Transport: *transport}, InventoryMetadata: *inventory, HTTPPlaintext: *plaintext, EventHeaders: *events, VisibleVolumes: *volumes, ProcessMetrics: *metrics, NetworkEndpoints: *endpoints}, env, compiledSource)
	if err != nil {
		fmt.Fprintln(stderr, "Native Windows acceptance requires manual exact-source approval for every scope.")
		return 2
	}
	defer grant.Close()
	options := native.Options{Expanded: grant.ExtensionsApproved(), Selection: grant.Selection(), ServiceArtifact: *service, ServiceSHA256: *serviceSHA, ControllerArtifact: *controller, ControllerSHA256: *controllerSHA}
	if _, err = native.New(options); err != nil {
		fmt.Fprintln(stderr, "Native acceptance artifact binding rejected.")
		return 2
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	result := execute(c, grant, options)
	b, err := gate.Encode(result)
	if err != nil {
		fmt.Fprintln(stderr, "Native acceptance evidence is invalid; raw details withheld.")
		return 1
	}
	n, err := out.Write(b)
	if err != nil || n != len(b) {
		return 1
	}
	if result.Status != "passed_native_subset" {
		return 1
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, environment(), executeNative))
}
