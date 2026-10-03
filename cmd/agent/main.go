// Command agent emits a single bounded, read-only JSON observation to stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"localrmm/internal/bundle"
	"localrmm/internal/collector"
)

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	support := flags.Bool("support-bundle", false, "emit a versioned, size-capped support bundle to stdout for manual review")
	once := flags.Bool("once", true, "emit one local sandbox observation to stdout and exit (only supported mode)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: agent [--once] [--support-bundle]\nTracebolt read-only local collector. One JSON sample to stdout; no network ingestion, host inventory, remote control, or persistent background mode.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !*once || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "agent supports one stdout-only sample; arguments cannot change collection paths or targets")
		return 2
	}
	sample := collector.Snapshot()
	if *support {
		data, err := bundle.Encode(sample)
		if err == nil {
			var n int
			n, err = stdout.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not encode or write support bundle:", err)
			return 1
		}
		return 0
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sample); err != nil {
		fmt.Fprintln(stderr, "could not encode observation:", err)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
