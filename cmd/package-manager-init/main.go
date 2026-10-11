// package-manager-init is a separately invoked, create-only local grant command.
// It is never called by lan-manager startup or the installer.
package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/packagecontroller"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("package-manager-init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "existing protected native package manager configuration")
	state := flags.String("enrollment-state", "", "existing protected enrollment database for read-only identity inspection")
	issuer := flags.String("enrollment-issuer", "", "protected public enrollment issuer certificate PEM; never a private key")
	ack := flags.Bool("ack-local-package-scope", false, "acknowledge this dedicated selected-package signing and durable operation scope")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *config == "" || *state == "" || *issuer == "" || !*ack {
		fmt.Fprintln(errOut, "--config, --enrollment-state, --enrollment-issuer and --ack-local-package-scope are required")
		return 2
	}
	publicPEM, err := lanconfig.ReadProtected(*issuer, false, 2*enrollmentcrypto.MaxCertificateBytes)
	if err != nil {
		fmt.Fprintln(errOut, "protected public enrollment issuer certificate could not be read")
		return 1
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 || len(block.Bytes) > enrollmentcrypto.MaxCertificateBytes || !bytes.Equal(publicPEM, pem.EncodeToMemory(block)) {
		fmt.Fprintln(errOut, "--enrollment-issuer requires exactly one public certificate PEM and no private material")
		return 1
	}
	authority := func(ctx context.Context, manager, device, incarnation string, now time.Time) error {
		return enrollmentstore.InspectPackageInitialization(ctx, *state, block.Bytes, manager, device, incarnation, now)
	}
	if err = packagecontroller.Initialize(context.Background(), *config, *ack, time.Now().UTC(), authority); err != nil {
		if errors.Is(err, enrollmentstore.ErrPackageRenewalUnsupported) {
			fmt.Fprintln(errOut, "native package actions are unsupported for automatically renewable identities; no package state was created")
		} else {
			fmt.Fprintln(errOut, "native package scope initialization failed; verify the exact enrollment identity and public issuer, and never reset existing or uncertain state")
		}
		return 1
	}
	fmt.Fprintln(out, "Native package manager state initialized. Endpoint/root acceptance and explicit local grants remain required.")
	return 0
}
