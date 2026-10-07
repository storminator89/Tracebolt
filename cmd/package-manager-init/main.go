// package-manager-init is a separately invoked, create-only local grant command.
// It is never called by lan-manager startup or the installer.
package main

import (
	"context"
	"flag"
	"fmt"
	"localrmm/internal/packagecontroller"
	"os"
	"time"
)

func main() {
	config := flag.String("config", "", "existing protected native package manager configuration")
	ack := flag.Bool("ack-local-package-scope", false, "acknowledge this dedicated selected-package signing and durable operation scope")
	flag.Parse()
	if flag.NArg() != 0 || *config == "" || !*ack {
		fmt.Fprintln(os.Stderr, "explicit protected configuration and --ack-local-package-scope are required")
		os.Exit(2)
	}
	if packagecontroller.Initialize(context.Background(), *config, *ack, time.Now().UTC()) != nil {
		fmt.Fprintln(os.Stderr, "native package scope initialization failed; existing or uncertain state must not be reset")
		os.Exit(1)
	}
	fmt.Println("Native package manager state initialized. Endpoint/root acceptance and explicit local grants remain required.")
}
