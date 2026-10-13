// macos-agent-service emits an inert launchd candidate and optional read-only
// local preflight. The explicit apply boundary has no native lifecycle adapter.
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
		fmt.Fprintln(out, "Tracebolt macOS launchd source candidate. Default: local read-only preflight as the existing dedicated _traceboltagent UID:GID, never root. Required flags: --service-identity UID:GID --agent-sha256 SHA256 --source-archive ABSOLUTE_PATH --source-sha256 SHA256. --profile basic-readonly-v1 (default) or macos-read-inventory-v1 selects only an already approved activated TLS enrollment. The root-owned agent and protected enrollment must already be at the fixed /Library/Application Support/TraceboltAgent paths. --render-only emits an unchecked deterministic JSON plan and complete plist without inspecting the host. --action install selects create-only lifecycle review; --apply is the separate mutation boundary. Its native adapter is unavailable and fails before any host inspection or mutation. Restart, upgrade, uninstall, account/key creation and permission changes are not implemented. A separately approved native installation and disposable Mac acceptance gate remain pending.")
		return 0
	}
	flags := flag.NewFlagSet("macos-agent-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", macosservice.BasicProfile, "Exact already-enrolled profile; inventory is explicit")
	action := flags.String("action", "", "install selects the create-only lifecycle foundation; native adapter unavailable")
	apply := flags.Bool("apply", false, "Explicit mutation boundary for --action install; native adapter unavailable")
	identity := flags.String("service-identity", "", "Exact reviewed dedicated nonroot UID:GID")
	agentHash := flags.String("agent-sha256", "", "Independently reviewed fixed macos-agent binary SHA-256")
	source := flags.String("source-archive", "", "Absolute protected local source archive path; never extracted")
	sourceHash := flags.String("source-sha256", "", "Independently reviewed source archive SHA-256")
	renderOnly := flags.Bool("render-only", false, "Render an unchecked candidate without host inspection")
	if flags.Parse(args) != nil || flags.NArg() != 0 || (*action != "" && *action != "install") || (*apply && *action != "install") || (*action != "" && *renderOnly) {
		fmt.Fprintln(errOut, "Request rejected. Use --help for the read-only planning flags. No native action was performed.")
		return 2
	}
	selection := macosservice.Request{Profile: *profile, ServiceIdentity: *identity, AgentSHA256: *agentHash, SourceArchive: *source, SourceSHA256: *sourceHash, RenderOnly: *renderOnly}
	if *action == "install" {
		return runInstall(ctx, selection, *apply, out, errOut, backend)
	}
	result, err := macosservice.Execute(ctx, selection, backend)
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

func runInstall(ctx context.Context, selection macosservice.Request, apply bool, out, errOut io.Writer, backend macosservice.Backend) int {
	lifecycle, _ := backend.(macosservice.InstallBackend)
	result, err := macosservice.Install(ctx, macosservice.InstallRequest{Selection: selection, Apply: apply}, lifecycle)
	if err == macosservice.ErrRequest {
		fmt.Fprintln(errOut, "Request rejected. Use exact profile, canonical nonroot UID:GID, lowercase SHA-256 values and protected fixed paths.")
		return 2
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	if err == macosservice.ErrUnavailable {
		fmt.Fprintln(errOut, "Native create-only installation is unavailable. No host inspection or mutation was attempted. Source fixtures do not establish installation or boot persistence.")
		return 1
	}
	if err != nil {
		fmt.Fprintln(errOut, "Create-only lifecycle blocked. Preserve all ownership, phase and enrollment state; do not retry an indeterminate operation or reset it.")
		return 1
	}
	fmt.Fprintln(errOut, "Lifecycle evidence returned. No native acceptance or boot persistence is established by this result.")
	return 0
}
