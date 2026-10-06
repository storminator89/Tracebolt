// action-setup is a local create-only manager provisioning seam, never a server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/actionsetup"
	"os"
	"time"
)

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("action-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "plan", "plan, apply, or capabilities")
	lan := flags.String("lan-config", "", "existing protected LAN configuration")
	enrollment := flags.String("enrollment-config", "", "existing protected enrollment configuration")
	device := flags.String("endpoint", "", "one existing activated endpoint ID")
	confirmation := flags.String("confirm-plan", "", "exact public plan digest approved by the local guide")
	dockerProbe := flags.Bool("docker-runtime-probe", false, "verify actual running manager PID 1 identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		actionsetup.RedactedError(errOut)
		return 2
	}
	if *mode == "capabilities" && *lan == "" && *enrollment == "" && *device == "" && *confirmation == "" && !*dockerProbe {
		fmt.Fprintln(out, `{"schemaVersion":"tracebolt.action-setup-capabilities.v1","managerCreateOnly":true}`)
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *mode == "status" && *confirmation == "" && *dockerProbe {
		if actionsetup.DockerProbeIdentity() != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		b, e := actionsetup.StatusManager(ctx, *lan, *enrollment, *device, time.Now().UTC())
		if e != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		if json.NewEncoder(out).Encode(b) != nil {
			return 2
		}
		return 0
	}
	if *mode == "plan" && *confirmation == "" {
		if *dockerProbe && actionsetup.DockerProbeIdentity() != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		p, e := actionsetup.PlanManager(ctx, *lan, *enrollment, *device, time.Now().UTC())
		if e != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		if json.NewEncoder(out).Encode(p) != nil {
			return 2
		}
		return 0
	}
	if *mode == "apply" && !*dockerProbe && *lan == "" && *enrollment == "" && *device == "" && *confirmation != "" {
		// Only a bounded public plan enters stdin. Private material is loaded locally.
		raw, e := io.ReadAll(io.LimitReader(in, 32769))
		var p actionsetup.ManagerPlan
		if e != nil || len(raw) > 32768 || json.Unmarshal(raw, &p) != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		b, e := actionsetup.ApplyManager(ctx, p, *confirmation, time.Now().UTC())
		if e != nil {
			actionsetup.RedactedError(errOut)
			return 2
		}
		if json.NewEncoder(out).Encode(b) != nil {
			return 2
		}
		return 0
	}
	actionsetup.RedactedError(errOut)
	return 2
}
func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
