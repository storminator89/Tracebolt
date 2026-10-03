// Command dev-agent makes one explicitly requested, bounded loopback delivery.
// It never installs a service, enrolls a device, or persists credentials.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/collector"
	"localrmm/internal/telemetry"
	"os"
	"runtime"
	"time"
)

func run(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("dev-agent", flag.ContinueOnError)
	f.SetOutput(stderr)
	endpoint := f.String("manager", "", "required literal http://127.0.0.1:PORT development manager")
	timeout := f.Duration("timeout", 5*time.Second, "total loopback request deadline (100ms to 10s)")
	f.Usage = func() {
		fmt.Fprintln(stderr, "Usage: dev-agent --manager http://127.0.0.1:8787\nSend one real, read-only Linux observation to an explicit --managed-preview manager, then exit. Local development only: no enrollment, background process, persistent credentials, service installation, or remote access.")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "dev-agent transport is limited to the Linux preview")
		return 2
	}
	client, err := telemetry.NewClient(*endpoint, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	raw, err := telemetry.EncodeForTransport(collector.Snapshot())
	if err != nil {
		fmt.Fprintln(stderr, "could not prepare bounded Linux telemetry")
		return 1
	}
	receipt, err := client.Send(context.Background(), raw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "could not write delivery receipt")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
