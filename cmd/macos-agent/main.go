// macos-agent reports only the explicitly enrolled basic or fresh inventory TLS scope. It never installs
// a service, creates a grant, repairs state or changes the endpoint identity.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/agentidentity"
	"localrmm/internal/agentloop"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type dependencies struct {
	inventory     func(string) (bool, error)
	inventoryOnce func(context.Context, string) error
	platform      string
	uid           func() int
	identity      func(string) bool
	validate      func(string) error
	once          func(context.Context, string) (lanclient.Report, error)
	foreground    func(context.Context, string, time.Duration, func(agentloop.Event) error) (agentloop.Summary, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, dependencies{
		platform: runtime.GOOS, uid: os.Geteuid, identity: agentidentity.Validate,
		validate:  enrollmentclient.ValidateMacOSHandoff,
		inventory: lanclient.IsMacOSInventoryConfig, inventoryOnce: enrollmentclient.RunMacOSInventoryOnce,
		once: func(ctx context.Context, path string) (lanclient.Report, error) {
			m, e := lanclient.Load(path)
			if e != nil {
				return lanclient.Report{}, e
			}
			return lanclient.Run(ctx, m)
		}, foreground: enrollmentclient.RunMacOSForeground,
	}))
}

func run(ctx context.Context, args []string, out, errOut io.Writer, d dependencies) int {
	f := flag.NewFlagSet("macos-agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "", "Absolute protected configuration from completed macOS enrollment")
	foreground := f.Bool("foreground", false, "Report until interrupted, with explicitly approved same-key renewal when configured")
	interval := f.Duration("interval", 30*time.Second, "Foreground interval, 15s to 1h")
	validate := f.Bool("validate-guided", false, "Read-only local validation; no collection, network or initialization")
	identity := f.String("service-identity", "", "Expected dedicated numeric UID:GID for separately approved launchd service")
	if f.Parse(args) != nil || f.NArg() != 0 || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path || *interval < 15*time.Second || *interval > time.Hour || (!*foreground && *interval != 30*time.Second) || (*validate && *foreground) || (*identity != "" && (!*foreground || *validate)) {
		fmt.Fprintln(errOut, "Usage: macos-agent --config ABS_PATH [--foreground --interval 30s] [--service-identity UID:GID] | --config ABS_PATH --validate-guided")
		return 2
	}
	if d.platform != "darwin" || d.uid == nil || d.uid() <= 0 || ctx == nil || (*identity != "" && (d.identity == nil || !d.identity(*identity))) {
		fmt.Fprintln(errOut, "macOS reporting requires the approved nonroot identity. No private state was opened.")
		return 2
	}
	if *validate {
		if d.validate == nil || d.validate(*path) != nil {
			fmt.Fprintln(errOut, "Guided state is invalid or stopped. Preserve the existing state.")
			return 1
		}
		fmt.Fprintln(out, "Guided state validated locally; no collection, network or initialization performed.")
		return 0
	}
	inventory := false
	if d.inventory != nil {
		var e error
		inventory, e = d.inventory(*path)
		if e != nil {
			fmt.Fprintln(errOut, "macOS profile configuration is invalid; preserve state.")
			return 1
		}
	}
	if inventory && *interval != 30*time.Second && *interval != time.Minute {
		fmt.Fprintln(errOut, "macOS inventory uses a fixed one-minute capture cadence.")
		return 2
	}
	encoder := json.NewEncoder(out)
	if *foreground {
		if d.foreground == nil {
			return 2
		}
		_, e := d.foreground(ctx, *path, *interval, func(event agentloop.Event) error {
			return encoder.Encode(struct {
				SchemaVersion string          `json:"schemaVersion"`
				Event         agentloop.Event `json:"event"`
			}{"tracebolt.agent-loop.v1", event})
		})
		if e != nil && !errors.Is(e, context.Canceled) {
			fmt.Fprintln(errOut, "macOS reporting stopped; preserve state and inspect its safe status.")
			return 1
		}
		return 0
	}
	if inventory {
		if d.inventoryOnce == nil {
			return 2
		}
		attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if e := d.inventoryOnce(attempt, *path); e != nil {
			fmt.Fprintln(errOut, "macOS inventory delivery was not confirmed. Preserve existing pending state.")
			return 1
		}
		if encoder.Encode(struct {
			SchemaVersion string `json:"schemaVersion"`
			Delivery      string `json:"delivery"`
		}{"tracebolt.macos-inventory-run.v1", "confirmed"}) != nil {
			return 1
		}
		return 0
	}
	if d.once == nil {
		return 2
	}
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report, e := d.once(attempt, *path)
	if e != nil {
		fmt.Fprintln(errOut, "macOS report was not confirmed. Preserve existing pending state.")
		return 1
	}
	if encoder.Encode(report) != nil {
		return 1
	}
	return 0
}
