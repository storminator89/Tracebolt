// macos-agent-service emits an inert launchd candidate and optional read-only
// local preflight. This program intentionally has no installation/apply path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/macosservice"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, macosservice.NewNativeBackend()))
}
func run(ctx context.Context, args []string, out, errOut io.Writer, backend macosservice.Backend) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Tracebolt macOS launchd source candidate. Default: local read-only preflight as the existing dedicated _traceboltagent UID:GID, never root. Required flags: --service-identity UID:GID --agent-sha256 SHA256 --source-archive ABSOLUTE_PATH --source-sha256 SHA256. The root-owned agent and protected activated basic TLS enrollment must already be at the fixed /Library/Application Support/TraceboltAgent paths. --render-only emits an unchecked deterministic JSON plan and complete plist without inspecting the host. No apply, install, bootstrap, restart, upgrade, uninstall, account/key creation or permission changes are implemented. A separately approved native installation and disposable Mac acceptance gate remain pending.")
		return 0
	}
	flags := flag.NewFlagSet("macos-agent-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	identity := flags.String("service-identity", "", "Exact reviewed dedicated nonroot UID:GID")
	agentHash := flags.String("agent-sha256", "", "Independently reviewed fixed macos-agent binary SHA-256")
	source := flags.String("source-archive", "", "Absolute protected local source archive path; never extracted")
	sourceHash := flags.String("source-sha256", "", "Independently reviewed source archive SHA-256")
	renderOnly := flags.Bool("render-only", false, "Render an unchecked candidate without host inspection")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(errOut, "Request rejected. Use --help for the read-only planning flags. No native action was performed.")
		return 2
	}
	result, err := macosservice.Execute(ctx, macosservice.Request{ServiceIdentity: *identity, AgentSHA256: *agentHash, SourceArchive: *source, SourceSHA256: *sourceHash, RenderOnly: *renderOnly}, backend)
	if err == macosservice.ErrRequest {
		fmt.Fprintln(errOut, "Request rejected. Use canonical nonroot UID:GID, lowercase SHA-256 values and an absolute source archive outside the fixed installation directory.")
		return 2
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	if err != nil {
		fmt.Fprintln(errOut, "Read-only preflight blocked. Review the failed check. No account, credential, file or service state was changed; do not bypass protection or reset retained enrollment.")
		return 1
	}
	if *renderOnly {
		fmt.Fprintln(errOut, "Unchecked candidate rendered. No host inspection or native action occurred.")
	} else {
		fmt.Fprintln(errOut, "Local read-only checks passed. This is not an installed service or boot-persistence result.")
	}
	fmt.Fprintln(errOut, "Installation is unavailable in this source candidate. Review the remaining native approval and acceptance gates in the result.")
	return 0
}
