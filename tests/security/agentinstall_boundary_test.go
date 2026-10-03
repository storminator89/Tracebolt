package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/agentinstall"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These fixtures have no filesystem, process, account, service, or network
// capabilities. They prove orchestration only: durable journaling, ownership,
// artifact publication, and identity retention remain platform-adapter duties.
type installBoundaryBackend struct {
	initial, locked agentinstall.HostFacts
	events          []string
	fail            string
	returnNil       bool
	onEvent         func(context.Context, string)
	rollbackFails   bool
}

type installBoundaryError struct{}

func (installBoundaryError) Error() string { panic("untrusted backend error was formatted") }

func (b *installBoundaryBackend) event(ctx context.Context, name string) error {
	b.events = append(b.events, name)
	if b.onEvent != nil {
		b.onEvent(ctx, name)
	}
	if name == b.fail || name == "rollback" && b.rollbackFails {
		return installBoundaryError{}
	}
	return nil
}

func (b *installBoundaryBackend) Inspect(ctx context.Context, _ agentinstall.Request) (agentinstall.HostFacts, error) {
	return b.initial, b.event(ctx, "inspect")
}

func (b *installBoundaryBackend) Begin(ctx context.Context, _ agentinstall.Request, _ agentinstall.Plan) (agentinstall.Transaction, error) {
	if err := b.event(ctx, "begin"); err != nil {
		return nil, err
	}
	if b.returnNil {
		var tx *installBoundaryTransaction
		return tx, nil
	}
	return &installBoundaryTransaction{b}, nil
}

type installBoundaryTransaction struct{ b *installBoundaryBackend }

func (t *installBoundaryTransaction) Inspect(ctx context.Context, _ agentinstall.Request) (agentinstall.HostFacts, error) {
	return t.b.locked, t.b.event(ctx, "inspect_locked")
}
func (t *installBoundaryTransaction) Before(ctx context.Context, op agentinstall.Operation) error {
	return t.b.event(ctx, "before:"+string(op))
}
func (t *installBoundaryTransaction) Apply(ctx context.Context, op agentinstall.Operation, _ agentinstall.Request) error {
	return t.b.event(ctx, "apply:"+string(op))
}
func (t *installBoundaryTransaction) Done(ctx context.Context, op agentinstall.Operation) error {
	return t.b.event(ctx, "done:"+string(op))
}
func (t *installBoundaryTransaction) Commit(ctx context.Context) error {
	return t.b.event(ctx, "commit")
}
func (t *installBoundaryTransaction) Rollback(ctx context.Context) error {
	return t.b.event(ctx, "rollback")
}
func (t *installBoundaryTransaction) Close() error {
	return t.b.event(context.Background(), "close")
}

func installBoundaryFixture(action agentinstall.Action) (agentinstall.Request, *installBoundaryBackend) {
	h := agentinstall.HostFacts{Linux: true, SystemdAvailable: true, Root: true, AccountCompatible: true, InstallationOwned: action != agentinstall.Install, Profile: "tls"}
	r := agentinstall.Request{Action: action, Apply: true, AgentBinary: "/fixture/lan-agent", AgentSHA256: strings.Repeat("1", 64), EnrollBinary: "/fixture/enroll-agent", EnrollSHA256: strings.Repeat("2", 64), BootstrapFile: "/fixture/bootstrap.json", BootstrapSHA256: strings.Repeat("3", 64), SourceArchive: "/fixture/source.tar", SourceSHA256: strings.Repeat("4", 64)}
	return r, &installBoundaryBackend{initial: h, locked: h}
}

func installBoundaryActions() []agentinstall.Action {
	return []agentinstall.Action{agentinstall.Install, agentinstall.Upgrade, agentinstall.Restart, agentinstall.Uninstall}
}

func installBoundaryOperations(action agentinstall.Action) []agentinstall.Operation {
	switch action {
	case agentinstall.Install:
		return []agentinstall.Operation{agentinstall.OpPrepare, agentinstall.OpStage, agentinstall.OpEnroll, agentinstall.OpValidate, agentinstall.OpPublish, agentinstall.OpStart}
	case agentinstall.Upgrade:
		return []agentinstall.Operation{agentinstall.OpStage, agentinstall.OpStop, agentinstall.OpValidate, agentinstall.OpPublish, agentinstall.OpStart}
	case agentinstall.Restart:
		return []agentinstall.Operation{agentinstall.OpStop, agentinstall.OpValidate, agentinstall.OpStart}
	case agentinstall.Uninstall:
		return []agentinstall.Operation{agentinstall.OpStop, agentinstall.OpDisable, agentinstall.OpRemove}
	default:
		panic("invalid test action")
	}
}

func installBoundaryEvents(action agentinstall.Action) []string {
	events := []string{"inspect", "begin", "inspect_locked"}
	for _, op := range installBoundaryOperations(action) {
		for _, phase := range []string{"before:", "apply:", "done:"} {
			events = append(events, phase+string(op))
		}
	}
	return append(events, "commit", "close")
}

func TestIndependentAgentInstallDryRunHasReadOnlyCapability(t *testing.T) {
	for _, action := range installBoundaryActions() {
		t.Run(string(action), func(t *testing.T) {
			r, b := installBoundaryFixture(action)
			r.Apply = false
			b.initial.Root = false
			out, err := agentinstall.Execute(context.Background(), r, b)
			if err != nil || !out.Plan.DryRun || out.Committed || out.RolledBack || !reflect.DeepEqual(b.events, []string{"inspect"}) {
				t.Fatal("dry-run reached a transaction or required elevation")
			}
		})
	}
}

func TestIndependentAgentInstallExactJournalOrdering(t *testing.T) {
	for _, action := range installBoundaryActions() {
		t.Run(string(action), func(t *testing.T) {
			r, b := installBoundaryFixture(action)
			out, err := agentinstall.Execute(context.Background(), r, b)
			if err != nil || !out.Committed || out.RolledBack || out.FailureStage != "" || !out.IdentityRetained {
				t.Fatal("successful transaction status is inconsistent")
			}
			if !reflect.DeepEqual(b.events, installBoundaryEvents(action)) {
				t.Fatal("operations escaped locked preflight, durable-intent ordering, or cleanup")
			}
		})
	}
}

func TestIndependentAgentInstallEveryJournalFailureStops(t *testing.T) {
	for _, action := range installBoundaryActions() {
		complete := installBoundaryEvents(action)
		// Every intent, application, completion, and commit boundary. The fake
		// may have completed a change before returning an error; recovery must
		// therefore be delegated, and no later operation may be dispatched.
		for index := 3; index < len(complete)-1; index++ {
			stage := complete[index]
			t.Run(string(action)+"/"+stage, func(t *testing.T) {
				r, b := installBoundaryFixture(action)
				b.fail = stage
				out, err := agentinstall.Execute(context.Background(), r, b)
				want := append(append([]string(nil), complete[:index+1]...), "rollback", "close")
				if err != agentinstall.ErrOperation || out.Committed || !out.RolledBack || !out.IdentityRetained || !reflect.DeepEqual(b.events, want) {
					t.Fatal("failed operation continued or skipped bounded rollback/close")
				}
				failure := stage
				if split := strings.IndexByte(stage, ':'); split >= 0 {
					failure = stage[split+1:]
				}
				if string(out.FailureStage) != failure {
					t.Fatal("safe failure stage does not identify the failed operation")
				}
			})
		}
	}
}

func TestIndependentAgentInstallLockedPreflightCannotBeSkipped(t *testing.T) {
	cases := []struct {
		name string
		edit func(*agentinstall.HostFacts)
	}{
		{"platform", func(h *agentinstall.HostFacts) { h.Linux = false }},
		{"systemd", func(h *agentinstall.HostFacts) { h.SystemdAvailable = false }},
		{"root", func(h *agentinstall.HostFacts) { h.Root = false }},
		{"account", func(h *agentinstall.HostFacts) { h.AccountCompatible = false }},
		{"ownership", func(h *agentinstall.HostFacts) { h.InstallationOwned = false }},
		{"profile", func(h *agentinstall.HostFacts) { h.Profile = "http-test" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := installBoundaryFixture(agentinstall.Upgrade)
			tc.edit(&b.locked)
			out, err := agentinstall.Execute(context.Background(), r, b)
			if err != agentinstall.ErrOperation || out.Committed || !out.RolledBack || !reflect.DeepEqual(b.events, []string{"inspect", "begin", "inspect_locked", "rollback", "close"}) {
				t.Fatal("stale pre-lock facts authorized an operation")
			}
		})
	}
}

func TestIndependentAgentInstallInvalidPlanNeverBegins(t *testing.T) {
	cases := []struct {
		name string
		edit func(*agentinstall.Request, *agentinstall.HostFacts)
	}{
		{"action", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.Action = "run-arbitrary-command" }},
		{"profile-missing", func(_ *agentinstall.Request, h *agentinstall.HostFacts) { h.Profile = "" }},
		{"profile-unknown", func(_ *agentinstall.Request, h *agentinstall.HostFacts) { h.Profile = "other" }},
		{"http-without-acknowledgment", func(_ *agentinstall.Request, h *agentinstall.HostFacts) { h.Profile = "http-test" }},
		{"tls-with-http-flag", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.InsecureHTTPTest = true }},
		{"unprivileged", func(_ *agentinstall.Request, h *agentinstall.HostFacts) { h.Root = false }},
		{"install-over-owned-installation", func(_ *agentinstall.Request, h *agentinstall.HostFacts) { h.InstallationOwned = true }},
		{"source-digest", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.SourceSHA256 = strings.Repeat("0", 64) }},
		{"sender-digest", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.AgentSHA256 = strings.Repeat("A", 64) }},
		{"enrollment-digest", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.EnrollSHA256 = "invalid" }},
		{"bootstrap-digest", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.BootstrapSHA256 = "" }},
		{"source-relative", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.SourceArchive = "relative/source" }},
		{"sender-noncanonical", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.AgentBinary = "/fixture/../lan-agent" }},
		{"enrollment-newline", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.EnrollBinary = "/fixture/enroll\nagent" }},
		{"bootstrap-nul", func(r *agentinstall.Request, _ *agentinstall.HostFacts) { r.BootstrapFile = "/fixture/boot\x00strap" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := installBoundaryFixture(agentinstall.Install)
			tc.edit(&r, &b.initial)
			out, err := agentinstall.Execute(context.Background(), r, b)
			if err == nil || out.Committed || !reflect.DeepEqual(b.events, []string{"inspect"}) {
				t.Fatal("invalid plan began a transaction")
			}
		})
	}
	// The HTTP-test flag is an explicit isolated profile acknowledgment; it
	// must not silently act as a downgrade switch for a TLS installation.
	r, b := installBoundaryFixture(agentinstall.Install)
	r.Apply, r.InsecureHTTPTest, b.initial.Profile = false, true, "http-test"
	if _, err := agentinstall.Execute(context.Background(), r, b); err != nil {
		t.Fatal("explicit HTTP-test plan was rejected")
	}
}

func TestIndependentAgentInstallCannotAdoptInstallationAppearingAfterPreflight(t *testing.T) {
	r, b := installBoundaryFixture(agentinstall.Install)
	b.locked.InstallationOwned = true
	out, err := agentinstall.Execute(context.Background(), r, b)
	if err != agentinstall.ErrOperation || out.Committed || !out.RolledBack || !reflect.DeepEqual(b.events, []string{"inspect", "begin", "inspect_locked", "rollback", "close"}) {
		t.Fatal("fresh install continued after an owned installation appeared under the lock")
	}
}

func TestIndependentAgentInstallRejectsUnavailableDependencies(t *testing.T) {
	r, b := installBoundaryFixture(agentinstall.Install)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := agentinstall.Execute(ctx, r, b); !errors.Is(err, context.Canceled) || len(b.events) != 0 {
		t.Fatal("pre-cancelled request reached the backend")
	}
	var nilBackend *installBoundaryBackend
	if _, err := agentinstall.Execute(context.Background(), r, nilBackend); err != agentinstall.ErrPreflight {
		t.Fatal("typed-nil backend was accepted")
	}
	if _, err := agentinstall.Execute(nil, r, b); err != agentinstall.ErrPreflight || len(b.events) != 0 {
		t.Fatal("nil context reached the backend")
	}
	for _, stage := range []string{"inspect", "begin", "inspect_locked", "typed-nil-transaction"} {
		t.Run(stage, func(t *testing.T) {
			r, b := installBoundaryFixture(agentinstall.Install)
			b.fail = stage
			b.returnNil = stage == "typed-nil-transaction"
			out, err := agentinstall.Execute(context.Background(), r, b)
			if err == nil || out.Committed || strings.Contains(strings.Join(b.events, ","), "apply:") {
				t.Fatal("unavailable dependency authorized an operation")
			}
		})
	}
}

func TestIndependentAgentInstallRollbackHasDetachedBoundedContext(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "local-fixture"))
	defer cancel()
	r, b := installBoundaryFixture(agentinstall.Install)
	b.fail = "apply:" + string(agentinstall.OpEnroll)
	rollbackSeen := false
	b.onEvent = func(ctx context.Context, stage string) {
		if stage == b.fail {
			cancel()
		}
		if stage == "rollback" {
			rollbackSeen = true
			deadline, ok := ctx.Deadline()
			remaining := time.Until(deadline)
			if ctx.Err() != nil || !ok || remaining <= 0 || remaining > 30*time.Second || ctx.Value(contextKey{}) != "local-fixture" {
				t.Error("rollback inherited cancellation or has no bounded cleanup window")
			}
		}
	}
	out, err := agentinstall.Execute(ctx, r, b)
	if err != agentinstall.ErrOperation || !rollbackSeen || !out.RolledBack {
		t.Fatal("cancelled failed operation did not attempt rollback")
	}
}

func TestIndependentAgentInstallCancellationPreventsNewSideEffectDispatch(t *testing.T) {
	for _, stage := range []string{"inspect", "before:" + string(agentinstall.OpStart), "before:" + string(agentinstall.OpRemove)} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			action := agentinstall.Install
			if strings.HasSuffix(stage, string(agentinstall.OpRemove)) {
				action = agentinstall.Uninstall
			}
			r, b := installBoundaryFixture(action)
			b.onEvent = func(_ context.Context, event string) {
				if event == stage {
					cancel()
				}
			}
			out, err := agentinstall.Execute(ctx, r, b)
			if err == nil || out.Committed {
				t.Fatal("cancelled transaction succeeded")
			}
			blocked := "begin"
			if strings.HasPrefix(stage, "before:") {
				blocked = "apply:" + strings.TrimPrefix(stage, "before:")
			}
			for _, event := range b.events {
				if event == blocked {
					t.Fatalf("cancellation during %s dispatched %s", stage, blocked)
				}
			}
		})
	}
}

func TestIndependentAgentInstallRollbackFailureIsNotReportedAsSuccess(t *testing.T) {
	r, b := installBoundaryFixture(agentinstall.Upgrade)
	b.fail, b.rollbackFails = "commit", true
	out, err := agentinstall.Execute(context.Background(), r, b)
	if err != agentinstall.ErrOperation || out.Committed || out.RolledBack || out.FailureStage != "commit" || b.events[len(b.events)-1] != "close" {
		t.Fatal("uncertain commit/recovery was reported successful or not closed")
	}
}

func TestIndependentAgentInstallPublicPlanDoesNotEchoRequestData(t *testing.T) {
	const marker = "PRIVATE-UNTRUSTED-PATH-DATA"
	r, b := installBoundaryFixture(agentinstall.Install)
	r.Apply = false
	r.AgentBinary, r.EnrollBinary, r.BootstrapFile = "/"+marker, "/"+marker, "/"+marker
	out, err := agentinstall.Execute(context.Background(), r, b)
	if err != nil {
		t.Fatal("fake read-only preflight fixture failed")
	}
	raw, err := json.Marshal(out)
	if err != nil || strings.Contains(string(raw), marker) || strings.Contains(string(raw), r.AgentSHA256) || strings.Contains(string(raw), r.EnrollSHA256) {
		t.Fatal("request-controlled data escaped the fixed public plan")
	}
}

func TestIndependentAgentInstallUnitUsesFixedSandboxedArgv(t *testing.T) {
	want := map[string]string{
		"User": "tracebolt-agent", "Group": "tracebolt-agent",
		"ExecStart":           "/opt/tracebolt-agent/lan-agent --config /var/lib/tracebolt-agent/enrollment/agent.json --foreground --interval 30s",
		"ConditionPathExists": "/var/lib/tracebolt-agent/enrollment/ready.json",
		"WorkingDirectory":    "/var/lib/tracebolt-agent", "ReadWritePaths": "/var/lib/tracebolt-agent",
		"Restart": "on-failure", "RestartSec": "30s", "RestartPreventExitStatus": "2",
		"StartLimitIntervalSec": "300s", "StartLimitBurst": "5", "TimeoutStopSec": "30s",
		"NoNewPrivileges": "true", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
		"ProtectSystem": "strict", "ProtectHome": "true", "PrivateTmp": "true", "PrivateDevices": "true", "UMask": "0077",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(agentinstall.Unit, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "Exec") && key != "ExecStart" {
			t.Fatal("unit introduced an unexpected executable hook")
		}
		if expected, ok := want[key]; ok {
			if seen[key] || value != expected {
				t.Fatal("unit security directive was overridden or changed")
			}
			seen[key] = true
		}
	}
	if len(seen) != len(want) {
		t.Fatal("unit lost a required privilege, fixed-path, or bounded-restart control")
	}
	// Read a repository template only. Never invoke systemd or write UnitPath.
	template, err := os.ReadFile("../../deploy/systemd/tracebolt-agent.service.in")
	if err != nil || string(template) != agentinstall.Unit {
		t.Fatal("shipped unit template drifted from the reviewed constant")
	}
}
