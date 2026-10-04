package main

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Reserved helper mode is recognized before flag parsing or any sender state
// access. Normal invocation falls through to the existing main body unchanged.
func journalReaderInvocation(args []string) (selected, exclusive bool) {
	for _, arg := range args {
		if arg == "--journal-reader" || arg == "-journal-reader" || strings.HasPrefix(arg, "--journal-reader=") || strings.HasPrefix(arg, "-journal-reader=") {
			return true, len(args) == 1 && arg == "--journal-reader"
		}
	}
	return false, false
}
func runJournalReader(ctx context.Context, exclusive bool, run func(context.Context) error, stderr io.Writer) int {
	if !exclusive || run == nil {
		fmt.Fprintln(stderr, "Tracebolt journal reader requires the exclusive --journal-reader mode.")
		return 2
	}
	if run(ctx) != nil {
		fmt.Fprintln(stderr, "Tracebolt journal reader unavailable; protected local authority or helper runtime rejected.")
		return 2
	}
	return 0
}
