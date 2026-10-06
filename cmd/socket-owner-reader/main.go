// socket-owner-reader is a separate, fixed-purpose native source candidate.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"localrmm/internal/socketowner"
)

func main() {
	// Argument-only build info does not initialize native authority or sockets.
	if len(os.Args) > 1 {
		os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, socketowner.Run))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, nil, os.Stdout, os.Stderr, socketowner.Run))
}
func run(ctx context.Context, args []string, out, errOut io.Writer, start func(context.Context) error) int {
	if len(args) == 1 && args[0] == "--build-info" {
		fmt.Fprintln(out, "Tracebolt socket-owner-reader source candidate; protocol="+socketowner.ProtocolVersion+"; policy="+socketowner.PolicyVersion+"; native acceptance unrun; deployment v2 activated-client contract required")
		return 0
	}
	if len(args) != 0 || start == nil {
		fmt.Fprintln(errOut, "socket-owner-reader: only no-argument socket activation or --build-info is supported")
		return 2
	}
	// The native runtime returns cancellation only after listener shutdown and
	// its admitted workers have joined. Startup/authority errors and deadlines
	// remain failures; cancellation must belong to this signal context.
	if e := start(ctx); e != nil && !(e == context.Canceled && ctx != nil && ctx.Err() == context.Canceled) {
		fmt.Fprintln(errOut, "socket-owner-reader: unavailable; protected authority or native prerequisite not verified")
		return 1
	}
	return 0
}
