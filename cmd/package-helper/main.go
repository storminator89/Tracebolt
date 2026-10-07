package main

import (
	"context"
	"localrmm/internal/packagehelper"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--initialize" && os.Args[2] == "--ack-local-root-package-scope" {
		if packagehelper.Initialize(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if packagehelper.RunBroker(ctx) != nil {
		os.Exit(1)
	}
}
