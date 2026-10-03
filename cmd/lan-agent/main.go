// lan-agent is currently a Linux one-shot foreground sender, not a service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"localrmm/internal/lanclient"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "", "Absolute protected preprovided agent configuration JSON")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN agent requires --config PATH; no service installation is performed.")
		os.Exit(2)
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Tracebolt LAN sender state is currently supported on Linux only; native ACL validation is pending for other platforms.")
		os.Exit(2)
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
