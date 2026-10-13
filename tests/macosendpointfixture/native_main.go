//go:build darwin && tracebolt_endpoint_native

// This separately built artifact is only for the manually reviewed hosted gate.
// The ordinary executable remains inert. Building this tag is not authorization.
package main

import (
	"context"
	"os"
)

const blockedResult = `{"schemaVersion":"tracebolt.macos-endpoint-fixture.v1","status":"blocked","reason":"native_execution_gate_unavailable","simulatedManager":true,"runtimeStarted":false}`

func main() {
	if len(os.Args) != 1 || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		os.Exit(2)
	}
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		s, err := f.Stat()
		if err != nil || s.Mode()&os.ModeNamedPipe == 0 {
			os.Exit(2)
		}
	}
	if runPeer(context.Background(), os.Stdin, os.Stdout) != nil {
		// Never emit raw protocol, secrets, paths or errors to public output.
		os.Exit(1)
	}
}
