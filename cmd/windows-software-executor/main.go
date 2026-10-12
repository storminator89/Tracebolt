// Command windows-software-executor is a separately approved foreground executor.
package main

import (
	"context"
	"flag"
	"localrmm/internal/windowssoftwareruntime"
	"os"
	"os/signal"
)

func main() {
	f := flag.NewFlagSet("windows-software-executor", flag.ContinueOnError)
	run := f.Bool("run-foreground", false, "")
	query := f.Bool("allow-observer-process-query", false, "")
	maintenance := f.Bool("acknowledge-exclusive-maintenance", false, "")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || !*run || !*maintenance {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if windowssoftwareruntime.Run(ctx, *query, *maintenance) != nil {
		os.Exit(1)
	}
}
