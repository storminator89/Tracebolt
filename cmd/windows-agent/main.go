// Command windows-agent is the explicitly requested, stdout-only Windows
// inventory preview. It does not enroll, transmit, install or persist anything.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"localrmm/internal/windowsevents"
	"localrmm/internal/windowsinventory"
)

type inventoryReader func(context.Context) (windowsinventory.Report, error)
type eventReader func(context.Context, []string, int) (windowsevents.Report, error)
type output struct {
	Inventory     windowsinventory.Report `json:"inventory"`
	EventMetadata *windowsevents.Report   `json:"eventMetadata,omitempty"`
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, windowsinventory.Collect, windowsevents.Collect)
}
func runWith(args []string, stdout, stderr io.Writer, inventory inventoryReader, events eventReader) int {
	flags := flag.NewFlagSet("windows-agent", flag.ContinueOnError)
	// The flag parser can echo caller-supplied strings. Keep those away from logs.
	flags.SetOutput(io.Discard)
	consent := flags.Bool("collect-read-only", false, "acknowledge one local CPU/RAM/system-volume, hostname/IP, process/service and machine-software snapshot to stdout")
	eventConsent := flags.Bool("event-metadata", false, "also acknowledge up to 25 recent System and Application event metadata rows per channel; no messages or EventData")
	help := flags.Bool("help", false, "show collection scope without collecting")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stderr)
			return 0
		}
		fmt.Fprintln(stderr, "Invalid Windows collector arguments. Use --help to review supported options.")
		return 2
	}
	if *help {
		usage(stdout)
		return 0
	}
	if flags.NArg() != 0 || !*consent {
		fmt.Fprintln(stderr, "Collection requires --collect-read-only after reviewing --help; positional arguments are not supported.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := inventory(ctx)
	if err != nil {
		if errors.Is(err, windowsinventory.ErrUnsupported) {
			fmt.Fprintln(stderr, "This collector requires native Windows.")
		} else {
			fmt.Fprintln(stderr, "Windows inventory could not complete; no output was emitted.")
		}
		return 1
	}
	result := output{Inventory: report}
	if *eventConsent {
		eventReport, err := events(ctx, []string{"Application", "System"}, 25)
		if err != nil && (eventReport.Source != windowsevents.Source || len(eventReport.Channels) != 2) {
			fmt.Fprintln(stderr, "Windows event metadata could not complete; no output was emitted.")
			return 1
		}
		result.EventMetadata = &eventReport
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) >= windowsinventory.MaxEncodedBytes {
		fmt.Fprintln(stderr, "Windows observation could not be encoded within its size limit.")
		return 1
	}
	data = append(data, '\n')
	n, err := stdout.Write(data)
	if err != nil || n != len(data) {
		fmt.Fprintln(stderr, "Windows observation could not be written completely.")
		return 1
	}
	return 0
}
func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: windows-agent --collect-read-only [--event-metadata]")
	fmt.Fprintln(out, "One bounded local JSON observation to stdout. Read scope: system CPU interval, physical RAM, system-volume capacity, hostname, up-interface IP addresses, visible process names/PIDs/thread counts, service names/status/PIDs, and machine uninstall-registry software name/version/publisher.")
	fmt.Fprintln(out, "Optional --event-metadata reads up to 25 recent Application and System event headers per channel: provider, event ID, level, timestamp and record ID. It excludes rendered messages, EventData, Security logs, usernames and SIDs.")
	fmt.Fprintln(out, "Review stdout privately; it contains local identifiers and inventory. No manager transport, enrollment, credentials, shell, elevation, service installation, background persistence or remote actions. Administrator elevation is not requested; denied/partial reads remain explicit. Windows Update/CVE and installed-service/enrollment acceptance are pending.")
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
