package main

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Reserved helper mode is recognized before flag parsing or any sender state
// access. Normal invocation falls through to the existing main body unchanged.
func actionHelperInvocation(args []string) (selected, exclusive bool) {
	for _, arg := range args {
		if arg == "--action-helper" || arg == "-action-helper" || strings.HasPrefix(arg, "--action-helper=") || strings.HasPrefix(arg, "-action-helper=") {
			return true, len(args) == 1 && arg == "--action-helper"
		}
	}
	return false, false
}
func runActionHelper(ctx context.Context, exclusive bool, run func(context.Context) error, stderr io.Writer) int {
	if !exclusive || run == nil {
		fmt.Fprintln(stderr, "Tracebolt action helper requires the exclusive --action-helper mode.")
		return 2
	}
	if run(ctx) != nil {
		fmt.Fprintln(stderr, "Tracebolt action helper unavailable; protected local authority or helper runtime rejected.")
		return 2
	}
	return 0
}
