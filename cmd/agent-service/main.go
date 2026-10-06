// agent-service plans or explicitly applies a fixed Linux/systemd installation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/agentinstall"
	"localrmm/internal/bootstrapfetch"
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
		fmt.Fprintln(out, "Tracebolt Linux/systemd agent service installer. Default: read-only preflight. Use --action install|upgrade|restart|uninstall. Install/upgrade require --agent-binary, --agent-sha256, --enroll-binary, --enroll-sha256, --source-archive and --source-sha256. Install also requires --bootstrap and --bootstrap-sha256. Add --apply only after reviewing the fixed-path plan. --resume explicitly reuses an exact retained preparation; --insecure-http-test requires a disposable HTTP test profile. For explicitly applied online bootstrap retrieval, replace --bootstrap with --manager-origin and --invitation-id; TLS also requires --server-ca-base64 containing public CA certificates. The same --bootstrap-sha256 is required. Online flags are rejected in dry-run before network or temporary-file creation. No invitation secret, executable download, reset or shell command is accepted.")
		return 0
	}
	f := flag.NewFlagSet("agent-service", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "install", "install, upgrade, restart or uninstall")
	expectedAgentOrigin := f.String("require-agent-origin", "", "Bind the read-admin preflight to its explicitly approved public agent ingress origin; requires --require-complete-profile")
	requireComplete := f.Bool("require-complete-profile", false, "Require a fresh managed-operations-v3 bootstrap before account or service changes; this validation does not grant optional scopes")
	pendingService := f.Bool("pending-service", false, "Explicit fresh v2 installation whose saved committed claim can wait for approval in the background; no observations before activation")
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
	managerOrigin := f.String("manager-origin", "", "Exact configured operator/enrollment origin for public bootstrap fetch; requires --apply")
	invitationID := f.String("invitation-id", "", "Public invitation identifier, never the one-time secret")
	serverCA := f.String("server-ca-base64", "", "Canonical standard base64 public TLS CA certificates; never a private key")
	insecure := f.Bool("insecure-http-test", false, "Acknowledge persistent reporting over unencrypted unauthenticated HTTP test transport")
	if f.Parse(args) != nil || f.NArg() != 0 {
		fmt.Fprintln(errOut, "Tracebolt service request rejected. Use the documented fixed-path flags; no shell command or invitation argument is accepted.")
		return 2
	}
	r := agentinstall.Request{Action: agentinstall.Action(*action), Apply: *apply, PendingService: *pendingService, RequireCompleteProfile: *requireComplete, ExpectedAgentOrigin: *expectedAgentOrigin, Resume: *resume, AgentBinary: *agent, AgentSHA256: *agentHash, EnrollBinary: *enroll, EnrollSHA256: *enrollHash, SourceArchive: *source, SourceSHA256: *sourceHash, BootstrapFile: *bootstrap, BootstrapSHA256: *bootstrapHash, InsecureHTTPTest: *insecure}
	online := *managerOrigin != "" || *invitationID != "" || *serverCA != ""
	if online && (!*apply || r.Action != agentinstall.Install || *bootstrap != "" || *managerOrigin == "" || *invitationID == "") {
		fmt.Fprintln(errOut, "Online public bootstrap retrieval requires explicit --apply, install action, exact manager origin and public invitation ID; it cannot be combined with --bootstrap. No download or temporary file was created. Use a local --bootstrap for read-only planning.")
		return 2
	}
	if *insecure {
		fmt.Fprintln(errOut, "WARNING: UNENCRYPTED HTTP TEST. Invitations and telemetry are visible; the manager and operator session are not authenticated by this transport. Use disposable test material.")
	}
	if online {
		var cleanup func() error
		var e error
		r, cleanup, e = prepareOnlineBootstrap(ctx, r, bootstrapfetch.Request{ManagerOrigin: *managerOrigin, InvitationID: *invitationID, ExpectedSHA256: *bootstrapHash, ServerCABase64: *serverCA, InsecureHTTPTest: *insecure}, agentinstall.ValidateOnlineBootstrapPreparation, bootstrapfetch.Fetch)
		if e != nil {
			fmt.Fprintln(errOut, "Public bootstrap retrieval could not be prepared or verified. Check local root/systemd/foreground terminal, selected artifact hashes and explicit manager trust. No installation was started.")
			return 1
		}
		defer func() {
			if cleanup() != nil {
				fmt.Fprintln(errOut, "Public bootstrap temporary-file cleanup was not confirmed; inspect the owned temporary snapshot locally.")
			}
		}()
	}
	fmt.Fprintln(errOut, "Checking fixed paths, artifact integrity, service ownership and retained identity before the requested operation.")
	result, e := agentinstall.Execute(ctx, r, backend)
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	reportOperation(r, result, e, errOut)
	if e != nil {
		return 1
	}
	return 0
}

// Keep stdout's machine-readable result unchanged. Human guidance uses only
// fixed strings and already validated action/state, never invitation or key data.
func reportOperation(r agentinstall.Request, result agentinstall.Result, err error, out io.Writer) {
	if err != nil {
		fmt.Fprintln(out, "Tracebolt service operation did not complete. Preserve the account and all identity/state files.")
		stages := map[agentinstall.Operation]string{
			agentinstall.OpPrepare:           "preparing the dedicated account and paths",
			agentinstall.OpStage:             "staging verified artifacts",
			agentinstall.OpEnroll:            "hidden-terminal enrollment",
			agentinstall.OpStop:              "stopping the owned service",
			agentinstall.OpValidate:          "validating retained enrollment and sender state",
			agentinstall.OpResetRestartState: "clearing the owned service failed status and start/restart counters",
			agentinstall.OpPublish:           "publishing owned binaries and unit",
			agentinstall.OpStart:             "starting and checking the service",
			agentinstall.OpDisable:           "disabling the owned service",
			agentinstall.OpRemove:            "removing owned installation files",
			"commit":                         "recording the durable installation result",
		}
		if stage, ok := stages[result.FailureStage]; ok {
			fmt.Fprintln(out, "Stopped while "+stage+".")
		} else {
			fmt.Fprintln(out, "Preflight or retained installer-state checks did not complete.")
		}
		if r.Action == agentinstall.Restart && (result.FailureStage == agentinstall.OpResetRestartState || result.FailureStage == agentinstall.OpStart || result.FailureStage == "commit") {
			fmt.Fprintln(out, "The owned service failed status and start/restart counters may already have been cleared; rollback does not restore this systemd bookkeeping.")
		}
		if result.RolledBack {
			fmt.Fprintln(out, "Owned transaction changes were rolled back; the service may remain stopped. A retained preparation needs the explicit --resume flow with exactly the same release, bootstrap and identity, after inspection. Do not create a new identity or blindly repeat the fresh-install command.")
		} else {
			fmt.Fprintln(out, "Recovery was not confirmed. Inspect the preflight/failure stage before retrying; do not add --resume, remove installer records or reset identity automatically.")
		}
		fmt.Fprintln(out, "Read-only service check: systemctl status --no-pager tracebolt-agent.service")
		return
	}
	if result.Plan.DryRun {
		fmt.Fprintln(out, "Read-only preflight passed. No account or service changes were made. Review the plan before deliberately using --apply.")
		return
	}
	if !result.Committed {
		return
	}
	switch r.Action {
	case agentinstall.Install:
		fmt.Fprintln(out, "Installation committed. tracebolt-agent.service is enabled for startup and its active process was checked.")
		if r.PendingService {
			fmt.Fprintln(out, "The service can wait for approval in the background. Compare the full local fingerprint and comparison value in the dashboard, then approve this device. Approval, activation and the first successful report must be checked there separately.")
		} else {
			fmt.Fprintln(out, "Check the first successful report in the dashboard separately.")
		}
	case agentinstall.Upgrade:
		fmt.Fprintln(out, "Upgrade committed. The active service process was checked; its previous startup enablement and existing identity were retained. Check fresh reporting in the dashboard.")
	case agentinstall.Restart:
		fmt.Fprintln(out, "Restart committed. The active service process was checked with the existing identity. Check fresh reporting in the dashboard.")
	case agentinstall.Uninstall:
		fmt.Fprintln(out, "Uninstall committed. Owned service files were removed; the account, public bootstrap and private identity/state were retained.")
	}
	if r.Action != agentinstall.Uninstall {
		fmt.Fprintln(out, "This result does not establish successful reporting or an actual operating-system reboot.")
	}
}
