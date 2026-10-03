// agent-service plans or explicitly applies a fixed Linux/systemd installation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/agentinstall"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, agentinstall.NewLinuxBackend()))
}
func run(ctx context.Context, args []string, out, errOut io.Writer, backend agentinstall.Backend) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Tracebolt Linux/systemd agent service installer. Default: read-only preflight. Use --action install|upgrade|restart|uninstall. Install/upgrade require --agent-binary, --agent-sha256, --enroll-binary, --enroll-sha256, --source-archive and --source-sha256. Install also requires --bootstrap and --bootstrap-sha256. Add --apply only after reviewing the fixed-path plan. --resume explicitly reuses an exact retained preparation; --insecure-http-test requires a disposable HTTP test profile. No invitation argument, reset, download or shell command is accepted.")
		return 0
	}
	f := flag.NewFlagSet("agent-service", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "install", "install, upgrade, restart or uninstall")
	resume := f.Bool("resume", false, "Resume the exact owned retained installation; never reset identity or change its bootstrap")
	apply := f.Bool("apply", false, "Explicitly apply the reviewed system account/service/file changes; default is read-only preflight")
	agent := f.String("agent-binary", "", "Absolute local Linux lan-agent binary")
	agentHash := f.String("agent-sha256", "", "Independently selected binary SHA-256")
	enroll := f.String("enroll-binary", "", "Absolute local Linux enroll-agent binary")
	enrollHash := f.String("enroll-sha256", "", "Independently selected enrollment binary SHA-256")
	source := f.String("source-archive", "", "Absolute local source archive; hashed without extraction")
	sourceHash := f.String("source-sha256", "", "Independently selected source archive SHA-256")
	bootstrap := f.String("bootstrap", "", "Absolute public enrollment bootstrap JSON")
	bootstrapHash := f.String("bootstrap-sha256", "", "Independently selected public bootstrap SHA-256")
	insecure := f.Bool("insecure-http-test", false, "Acknowledge persistent reporting over unencrypted unauthenticated HTTP test transport")
	if f.Parse(args) != nil || f.NArg() != 0 {
		fmt.Fprintln(errOut, "Tracebolt service request rejected. Use the documented fixed-path flags; no shell command or invitation argument is accepted.")
		return 2
	}
	r := agentinstall.Request{Action: agentinstall.Action(*action), Apply: *apply, Resume: *resume, AgentBinary: *agent, AgentSHA256: *agentHash, EnrollBinary: *enroll, EnrollSHA256: *enrollHash, SourceArchive: *source, SourceSHA256: *sourceHash, BootstrapFile: *bootstrap, BootstrapSHA256: *bootstrapHash, InsecureHTTPTest: *insecure}
	if *insecure {
		fmt.Fprintln(errOut, "WARNING: UNENCRYPTED HTTP TEST. Invitations and telemetry are visible; the manager and operator session are not authenticated by this transport. Use disposable test material.")
	}
	result, e := agentinstall.Execute(ctx, r, backend)
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	if e != nil {
		fmt.Fprintln(errOut, "Tracebolt service operation did not complete. Inspect the safe failure stage, retain identity/state and resolve preflight or transaction recovery before retrying.")
		return 1
	}
	return 0
}
