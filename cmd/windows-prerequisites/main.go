// Command windows-prerequisites exposes only read-only host-policy measurement.
// It has no service/ACL/credential mutation or manual-acceptance dispatch mode.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"os"
	"strings"
	"time"
)

var compiledSource = "unbound"

const schema = "tracebolt.windows-prerequisites.v2"

type report struct {
	Schema string `json:"schema"`
	Source string `json:"source"`
	native.PrerequisiteObservation
	ReadOnly                            bool `json:"readOnly"`
	NativeServiceAcceptance             bool `json:"nativeServiceAcceptance"`
	EffectiveServiceTokenAccessVerified bool `json:"effectiveServiceTokenAccessVerified"`
	HostMutated                         bool `json:"hostMutated"`
}

func run(ctx context.Context, args []string, out, stderr io.Writer, inspect func(context.Context) native.PrerequisiteObservation) int {
	if ctx == nil || inspect == nil || len(args) != 2 || args[0] != "--read-only-prerequisites" || !gate.ValidSource(compiledSource) || args[1] != "--expected-source="+compiledSource {
		fmt.Fprintln(stderr, "Read-only Windows prerequisite source/arguments rejected.")
		return 2
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p := inspect(c)
	if !p.Valid() {
		fmt.Fprintln(stderr, "Read-only prerequisite evidence invalid; raw details withheld.")
		return 1
	}
	r := report{Schema: schema, Source: compiledSource, PrerequisiteObservation: p, ReadOnly: true}
	b, err := json.Marshal(r)
	if err != nil || len(b) > 2048 || strings.Contains(string(b), "\n") {
		return 1
	}
	b = append(b, '\n')
	n, err := out.Write(b)
	if err != nil || n != len(b) {
		return 1
	}
	return 0
}
func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, native.InspectPrerequisites))
}
