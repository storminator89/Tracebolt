//go:build windows && tracebolt_fresh_native

package main

// This test is absent from ordinary builds/tests. Explicit build tags alone are
// not permission: the distinct exact-source/artifact/machine gate runs first.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// Empty in every unpinned build. The manual builder must bind the reviewed SHA.
var freshCompiledSource string

const freshSuccessMarker = "TRACEBOLT_FRESH_COORDINATOR_VERIFIED_V1"

func freshArtifactHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", freshgate.ErrGuard
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() < 1 || s.Size() > 128<<20 {
		return "", freshgate.ErrGuard
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if e != nil || n != s.Size() {
		return "", freshgate.ErrGuard
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func freshAuthorization() (*freshgate.Grant, string, string, error) {
	get := os.Getenv
	yes := func(n string) bool { return get("TRACEBOLT_FRESH_APPROVE_"+n) == "true" }
	deadline, e := strconv.ParseInt(get("TRACEBOLT_FRESH_EXPIRES_UNIX"), 10, 64)
	if e != nil {
		return nil, "", "", setupFailed("authorization_expiry", freshgate.ErrGuard)
	}
	a := freshgate.Approval{Profile: get("TRACEBOLT_FRESH_PROFILE"), Source: get("TRACEBOLT_FRESH_SOURCE"), TestSHA256: get("TRACEBOLT_FRESH_TEST_SHA256"), ServiceSHA256: get("TRACEBOLT_FRESH_SERVICE_SHA256"), Machine: get("TRACEBOLT_FRESH_MACHINE"), RunID: get("TRACEBOLT_FRESH_RUN_ID"), Attempt: get("TRACEBOLT_FRESH_ATTEMPT"), ExpiresUnix: deadline, Services: yes("SERVICES"), Identity: yes("IDENTITY"), AppACLs: yes("APP_ACLS"), FiveReadScopes: yes("FIVE_READ_SCOPES"), SyntheticConsole: yes("SYNTHETIC_CONSOLE"), LoopbackTLS: yes("LOOPBACK_TLS"), RetainForVMDisposal: yes("RETAIN_FOR_VM_DISPOSAL"), StopOwnedService: yes("STOP_OWNED_SERVICE")}
	// Preliminary pure grant verification occurs before reading artifact files.
	r := freshgate.Runtime{Source: get("GITHUB_SHA"), CompiledSource: freshCompiledSource, TestSHA256: a.TestSHA256, ServiceSHA256: a.ServiceSHA256, Machine: get("COMPUTERNAME"), RunID: get("GITHUB_RUN_ID"), Attempt: get("GITHUB_RUN_ATTEMPT"), Repository: get("GITHUB_REPOSITORY"), Event: get("GITHUB_EVENT_NAME"), Actions: get("GITHUB_ACTIONS"), RunnerEnvironment: get("RUNNER_ENVIRONMENT"), RunnerOS: get("RUNNER_OS"), RepositoryOwner: get("GITHUB_REPOSITORY_OWNER"), RepositoryOwnerID: get("GITHUB_REPOSITORY_OWNER_ID"), Actor: get("GITHUB_ACTOR"), ActorID: get("GITHUB_ACTOR_ID"), TriggeringActor: get("GITHUB_TRIGGERING_ACTOR")}
	preliminary, e := freshgate.Authorize(a, r, time.Now)
	if e != nil {
		return nil, "", "", setupFailed("authorization_preliminary", freshgate.ErrGuard)
	}
	preliminary.Close()
	host, e := os.Hostname()
	if e != nil || host != a.Machine {
		return nil, "", "", setupFailed("authorization_hostname", freshgate.ErrGuard)
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, "", "", setupFailed("authorization_executable", freshgate.ErrGuard)
	}
	service := get("TRACEBOLT_FRESH_SERVICE_ARTIFACT")
	r.Machine = host
	r.TestSHA256, e = freshArtifactHash(exe)
	if e != nil {
		return nil, "", "", setupFailed("authorization_test_hash", freshgate.ErrGuard)
	}
	r.ServiceSHA256, e = freshArtifactHash(service)
	if e != nil {
		return nil, "", "", setupFailed("authorization_service_hash", freshgate.ErrGuard)
	}
	g, e := freshgate.Authorize(a, r, time.Now)
	if e != nil {
		e = setupFailed("authorization_final", e)
	}
	return g, exe, service, e
}
func freshConsent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV3, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: readSetupScopes(), Acknowledged: true}
}

// Child mode bypasses testing's PASS/traces entirely, preserving a finite console
// protocol. Ordinary tagged tests call m.Run; untagged builds contain none of it.
func TestMain(m *testing.M) {
	if os.Getenv("TRACEBOLT_FRESH_ROLE") == "child" {
		os.Exit(freshChildMain())
	}
	os.Exit(m.Run())
}
func freshChildMain() (code int) {
	code = freshgate.ChildFailureExitCode("unknown", "unknown")
	defer func() {
		if recover() != nil {
			code = freshgate.ChildFailureExitCode("child_panic", "recovered")
		}
	}()
	if len(os.Args) != 4 || os.Args[1] != "-test.run=^TestFreshReadConPTYNative$" || os.Args[2] != "-test.count=1" || os.Args[3] != "-test.timeout=14m" {
		return freshgate.ChildFailureExitCode("child_arguments", "rejected")
	}
	g, _, _, e := freshAuthorization()
	if e != nil {
		return freshChildFailureCode(e)
	}
	defer g.Close()
	ctx, cancel := context.WithDeadline(context.Background(), g.Deadline().Add(-2*time.Minute))
	defer cancel()
	if e := freshChild(ctx, g); e != nil {
		return freshChildFailureCode(e)
	}
	return 0
}

func TestFreshReadConPTYNative(t *testing.T) {
	g, exe, service, e := freshAuthorization()
	if e != nil {
		t.Skip("separate exact-source fresh native approval unavailable")
		return
	}
	defer g.Close()
	role := os.Getenv("TRACEBOLT_FRESH_ROLE")
	if role != "controller" {
		t.Fatal("fresh native role refused")
	}
	ctx, cancel := context.WithDeadline(context.Background(), g.Deadline().Add(-2*time.Minute))
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	defer func() {
		if recover() != nil {
			t.Fatal("fresh native operation incomplete; retained state requires VM disposal")
		}
	}()

	r := freshController(ctx, g, exe, service)
	raw, e := r.Encode()
	if e != nil {
		t.Fatal("fresh native finite evidence rejected")
	}
	fmt.Printf("fresh-native-report=%s\n", raw)
	if r.Status != "passed_fresh_native_subset" {
		t.Fatal("fresh native subset incomplete; retained state requires VM disposal")
	}
}

func freshReadReceipt(layout windowsservice.Layout) (installReceipt, error) {
	store, e := windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))
	if e != nil {
		return installReceipt{}, freshgate.ErrGuard
	}
	defer store.Close()
	raw, e := store.Read("receipt.json")
	if e != nil {
		return installReceipt{}, freshgate.ErrGuard
	}
	defer clear(raw)
	var r installReceipt
	if len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil {
		return r, freshgate.ErrGuard
	}
	canonical, e := json.Marshal(r)
	if e != nil || !reflect.DeepEqual(raw, canonical) || r.Service.Layout != layout || r.Version != 2 || r.ReadSetup == nil || validateReadSetupConsent(r.ReadSetup.Consent) != nil || !reflect.DeepEqual(r.ReadSetup.Consent, freshConsent()) {
		return r, freshgate.ErrGuard
	}
	if store.Close() != nil {
		return r, freshgate.ErrGuard
	}
	return r, nil
}
func freshVerifyCompleted(ctx context.Context, g *freshgate.Grant) (installReceipt, error) {
	if (ctx.Err() != nil || !g.Check()) || ctx.Err() != nil {
		return installReceipt{}, setupFailed("completion_context", freshgate.ErrGuard)
	}
	layout, e := windowsservice.ResolveLayout()
	if e != nil {
		return installReceipt{}, setupFailed("completion_layout", freshgate.ErrGuard)
	}
	r, e := freshReadReceipt(layout)
	if e != nil || !completeReadSetup(r) {
		return r, setupFailed("completion_receipt", freshgate.ErrGuard)
	}
	p := filepath.Join(layout.EnrollmentRoot, "agent.json")
	binding, e := lanclient.WindowsCapabilityIdentity(p, r.ReadSetup.Consent)
	if e != nil || binding != r.ReadSetup.SenderBinding {
		return r, setupFailed("completion_identity", freshgate.ErrGuard)
	}
	digests, e := lanclient.WindowsCapabilityGrantDigests(p, r.ReadSetup.Consent)
	if e != nil || !reflect.DeepEqual(digests, r.ReadSetup.GrantDigests) {
		return r, setupFailed("completion_grants", freshgate.ErrGuard)
	}
	if native.VerifyFreshServiceToken(ctx, r.Service) != nil {
		return r, setupFailed("completion_token", freshgate.ErrGuard)
	}
	return r, nil
}
func freshChild(ctx context.Context, g *freshgate.Grant) error {
	// No injected secret/enrollment/setup/grant/start callback. The production
	// function opens CONIN$ and performs all its real SCM and protected-store work.
	if ctx.Err() != nil || !g.Check() {
		return setupFailed("child_context", freshgate.ErrGuard)
	}
	if _, e := installReadObservation(ctx, os.Getenv("TRACEBOLT_FRESH_BOOTSTRAP"), freshConsent(), os.Stdout, os.Stderr); e != nil {
		return setupFailed("coordinator", e)
	}
	var completionErr error
	if e := freshAwait(ctx, func() bool { _, completionErr = freshVerifyCompleted(ctx, g); return completionErr == nil }); e != nil {
		if completionErr != nil {
			return completionErr
		}
		return setupFailed("completion_wait", e)
	}
	if ctx.Err() != nil || !g.Check() {
		return setupFailed("success_context", freshgate.ErrGuard)
	}
	_, e := fmt.Fprint(os.Stdout, "\r\n"+freshSuccessMarker+"\r\n")
	if e != nil {
		return setupFailedCategory("success_write", "failed", e)
	}
	return nil
}
func freshAwait(ctx context.Context, condition func() bool) error {
	for {
		if ctx.Err() != nil {
			return freshgate.ErrGuard
		}
		if condition() {
			return nil
		}
		select {
		case <-ctx.Done():
			return freshgate.ErrGuard
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func freshController(ctx context.Context, g *freshgate.Grant, exe, service string) (r freshgate.Report) {
	r = freshgate.NewReport(freshCompiledSource)
	r.ApprovalValidated = true
	if ctx.Err() != nil || !g.Check() {
		return r
	}
	r.NativeActionsAttempted = true
	r.ControllerStage = "provisioning"
	r.Status = "failed"
	d, e := native.New(native.Options{Expanded: true, Selection: g.Selection(), ServiceArtifact: service, ServiceSHA256: os.Getenv("TRACEBOLT_FRESH_SERVICE_SHA256"), ControllerArtifact: exe, ControllerSHA256: os.Getenv("TRACEBOLT_FRESH_TEST_SHA256")})
	if e != nil {
		return r
	}
	defer d.ReleaseFreshProvisioning()
	defer func() {
		r.AppStateRetainedForVMDisposal = d.Evidence().CleanupRetained
		r.PlatformDisposalRequired = r.AppStateRetainedForVMDisposal
		r.ServiceAndAppStateRetained = r.AppStateRetainedForVMDisposal
	}()
	if d.Preflight(ctx) != nil || (ctx.Err() != nil || !g.Check()) || d.Provision(ctx, g) != nil {
		return r
	}
	r.AppStateRetainedForVMDisposal = true
	if ctx.Err() != nil || !g.Check() {
		return r
	}
	r.ControllerStage = "fixture"
	f, e := fixture.StartExpanded(ctx, g.Selection())
	if e != nil {
		return r
	}
	defer func() {
		e := f.Close()
		v := f.Evidence()
		r.FixtureClosed = e == nil && v.Closed
		r.Inventory = v.Inventory
		r.Extensions = v.Extensions
		if !r.FixtureClosed {
			r.Status = "failed"
		}
	}()
	secret, e := f.Secret(ctx)
	if e != nil {
		return r
	}
	defer clear(secret)
	guard, e := freshgate.NewOutputGuard(secret)
	if e != nil {
		return r
	}
	defer guard.Close()
	r.ControllerStage = "bootstrap"
	layout, e := windowsservice.ResolveLayout()
	if e != nil || (ctx.Err() != nil || !g.Check()) {
		return r
	}
	// This extra input store is test-only, contains PUBLIC bootstrap only, and is
	// retained with all app resources for the explicitly approved VM disposal.
	input, e := windowsstate.Open(layout.StateRoot+"-acceptance-input", windowsstate.Options{InstallerOnly: true, Names: []string{"bootstrap.json"}, LockName: "acceptance.lock", TempName: "acceptance.tmp", MaxBytes: 64 << 10, Create: true})
	if e != nil {
		return r
	}
	bootstrapRaw, e := json.Marshal(f.Bootstrap())
	if e != nil {
		input.Close()
		return r
	}
	e = input.Write("bootstrap.json", bootstrapRaw)
	clear(bootstrapRaw)
	closeErr := input.Close()
	if e != nil || closeErr != nil {
		return r
	}
	r.ControllerStage = "launch"
	child, e := startFreshPTY(ctx, g, exe, filepath.Join(layout.StateRoot+"-acceptance-input", "bootstrap.json"))
	if e != nil {
		return r
	}
	defer func() {
		if !r.OwnedChildReaped {
			r.Status = "failed"
			return
		}
		cleanupCtx, cancel := context.WithDeadline(context.Background(), g.Deadline())
		defer cancel()
		q, err := freshStopOwnedService(cleanupCtx, g, layout, func(phase string) { r.CoordinatorPhase = freshDiagnosticPhase(phase) })
		r.OwnedServiceStopped = q.Stopped
		r.ServiceDisabled = q.Disabled
		r.AutomaticStartConfigurationRetained = q.Automatic
		if err != nil || !q.Stopped {
			r.Status = "failed"
		}
	}()
	defer func() {
		// Snapshot only the existing waiter result before any forced teardown.
		r.NaturalChildExit, r.ChildFailureStage, r.ChildFailureCategory = child.naturalDiagnostic()
		reaped, closed := child.Close()
		r.OwnedChildReaped = reaped
		r.ConsoleClosed = closed
		if !reaped || !closed {
			r.Status = "failed"
		}
	}()
	// Only one goroutine reads/feeds output; the main loop consumes finite state.
	r.ControllerStage = "session"
	r.SessionOutcome, e = child.Run(ctx, guard, func() error {
		if ctx.Err() != nil || !g.Check() {
			return freshgate.ErrGuard
		}
		receipt, e := freshReadReceipt(layout)
		if e == nil {
			r.CoordinatorPhase = freshDiagnosticPhase(receipt.ReadSetup.Phase)
		}
		if e != nil || receipt.Service.Version != 2 || !receipt.Prepared || receipt.ReadSetup.Phase != "claim-started" {
			return freshgate.ErrGuard
		}
		s, e := windowsservice.InspectFreshReadSetup(ctx, receipt.Service)
		if e != nil || s.State != windowsservice.Stopped || s.Configuration.StartType != 4 {
			return freshgate.ErrGuard
		}
		if lanclient.WindowsCapabilityScopesAbsent(layout.StateRoot, receipt.Service.ServiceSID) != nil {
			return freshgate.ErrGuard
		}
		r.DisabledStageVerified = true
		r.SyntheticInput = true
		return child.Input(secret)
	}, func() error {
		if ctx.Err() != nil || !g.Check() {
			return freshgate.ErrGuard
		}
		fp, comparison, ok := guard.PublicTrust()
		if !ok {
			return freshgate.ErrGuard
		}
		if f.Evidence().State != enrollmentstate.ClaimedPending {
			return errFreshPending
		}
		return f.Approve(fp, comparison)
	})
	r.OutputRejection = guard.RejectionReason()
	if e != nil {
		return r
	}
	r.NoEchoVerified = true
	r.ControllerStage = "verify_completed"
	verified, e := freshVerifyCompleted(ctx, g)
	if e != nil {
		return r
	}
	r.CoordinatorPhase = freshDiagnosticPhase(verified.ReadSetup.Phase)
	r.ReceiptAndGrantsVerified = true
	r.LimitedServiceTokenVerified = true
	r.HiddenConsoleExercised = true
	r.ControllerStage = "observe_inventory"
	if freshAwait(ctx, func() bool { v := f.Evidence(); return v.Inventory.Usable() && v.Extensions.Usable() }) != nil {
		return r
	}
	r.ControllerStage = "completed"
	r.FreshOrchestrationAcceptance = true
	r.Status = "passed_fresh_native_subset"
	return r
}

// Stop only an exact protected receipt-bound service after the console child has
// exited. Unknown/partial ownership never receives Stop/Delete/config changes.
// Disabled staging needs no mutation; an exact automatic successor gets Stop
// only. The service and all protected state are retained for VM disposal.
type freshQuiescence struct{ Stopped, Disabled, Automatic bool }

func freshStopOwnedService(ctx context.Context, g *freshgate.Grant, layout windowsservice.Layout, observePhase func(string)) (freshQuiescence, error) {
	if ctx.Err() != nil || !g.Check() {
		return freshQuiescence{}, freshgate.ErrGuard
	}
	r, e := freshReadReceipt(layout)
	if e == nil {
		observePhase(r.ReadSetup.Phase)
	}
	if e != nil || !r.Service.Complete {
		return freshQuiescence{}, freshgate.ErrGuard
	}
	service := r.Service
	if service.Version == 2 {
		service, e = windowsservice.ReconcileFreshReadSetup(ctx, service)
		if e != nil {
			return freshQuiescence{}, freshgate.ErrGuard
		}
		if service.Version == 2 {
			s, e := windowsservice.InspectFreshReadSetup(ctx, service)
			if e != nil || s.State != windowsservice.Stopped || s.Configuration.StartType != 4 {
				return freshQuiescence{}, freshgate.ErrGuard
			}
			return freshQuiescence{Stopped: true, Disabled: true}, nil
		}
	} else if !completeReadSetup(r) {
		return freshQuiescence{}, freshgate.ErrGuard
	}
	err := freshgate.StopOwned(ctx, freshgate.OwnedStopSteps{
		Check: g.Check,
		Inspect: func() (windowsservice.State, error) {
			s, e := windowsservice.InspectOwned(ctx, service)
			return s.State, e
		},
		Stop: func() error { _, e := windowsservice.ApplyStop(ctx, service); return e },
		Pause: func(c context.Context) error {
			select {
			case <-c.Done():
				return freshgate.ErrGuard
			case <-time.After(100 * time.Millisecond):
				return nil
			}
		},
	})
	if err != nil {
		return freshQuiescence{}, err
	}
	return freshQuiescence{Stopped: true, Automatic: true}, nil
}

// Only copy a known lifecycle phase from an already-required protected receipt
// read. Diagnostic collection never opens an additional native resource.
func freshDiagnosticPhase(phase string) string {
	switch phase {
	case "install-started", "claim-started", "activation-started", "grants-started", "grants-incomplete", "grants-verified", "startup-transition-started", "configured":
		return phase
	default:
		return "unknown"
	}
}
