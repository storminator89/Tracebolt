// Command windows-update-executor is an administrator-launched foreground
// source candidate. It has no service installer, provisioning or alternate paths.
package main

import (
	"context"
	"localrmm/internal/windowsupdateruntime"
	"os"
	"os/signal"
)

func main() {
	allow := false
	if len(os.Args) == 3 && os.Args[1] == "--run-foreground" && os.Args[2] == "--allow-observer-process-query" {
		allow = true
	} else if len(os.Args) != 2 || os.Args[1] != "--run-foreground" {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if windowsupdateruntime.Run(ctx, allow) != nil {
		os.Exit(1)
	}
}
