// Public configuration verification on the build host. Input is bounded and
// read from stdin; the tool emits neither its contents nor parser errors.
package main

import (
	"io"
	"os"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (64<<10)+1))
	if err != nil || !validPublicBootstrap(raw) {
		os.Exit(1)
	}

}

func validPublicBootstrap(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return false
	}
	b, err := enrollmentclient.ParseBootstrap(raw)
	return err == nil && b.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory
}
