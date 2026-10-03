// lan-agent is a Linux read-only sender with optional foreground scheduling.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"localrmm/internal/agentloop"
	"localrmm/internal/lanclient"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "", "Absolute protected preprovided agent configuration JSON")
	identity := flag.String("service-identity", "", "Expected numeric service UID:GID; rejects additional groups before state access")
	validate := flag.Bool("validate-guided", false, "Validate local guided handoff and existing ledger without collection or network")
	foreground := flag.Bool("foreground", false, "Repeat bounded read-only reports until interrupted; does not install a service")
	interval := flag.Duration("interval", 30*time.Second, "Foreground report interval, 15s to 1h")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN agent requires --config PATH; no service installation is performed.")
		os.Exit(2)
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN sender state is currently supported on Linux only; native ACL validation is pending for other platforms.")
		os.Exit(2)
	}
	if *identity != "" && (!*foreground || *validate || !serviceIdentity(*identity)) {
		fmt.Fprintln(os.Stderr, "Tracebolt service identity rejected before private-state access.")
		os.Exit(2)
	}
	if *validate {
		if *foreground || *interval != 30*time.Second || lanclient.ValidateGuidedHandoff(*path) != nil {
			fmt.Fprintln(os.Stderr, "Tracebolt guided handoff validation failed; identity and state preserved.")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "Tracebolt guided handoff validated locally; no collection or network request performed.")
		return
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
