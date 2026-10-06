package agentinstall

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeBackend struct {
	facts           HostFacts
	events          []string
	fail            string
	onApply         func(Operation)
	begun           int
	activeOperation Operation
}

func (f *fakeBackend) Inspect(context.Context, Request) (HostFacts, error) {
	f.events = append(f.events, "inspect")
	return f.facts, nil
}
func (f *fakeBackend) Begin(context.Context, Request, Plan) (Transaction, error) {
	f.events = append(f.events, "begin")
	f.begun++
	return &fakeTransaction{f}, nil
}

type fakeTransaction struct{ f *fakeBackend }

func (t *fakeTransaction) Inspect(ctx context.Context, r Request) (HostFacts, error) {
	return t.f.Inspect(ctx, r)
}
func (t *fakeTransaction) event(s string) error {
	t.f.events = append(t.f.events, s)
	if t.f.fail == s {
		return errors.New("untrusted backend error must not appear in result")
	}
	return nil
}
func (t *fakeTransaction) Before(_ context.Context, op Operation) error {
	if e := t.event("before:" + string(op)); e != nil {
		return e
	}
	t.f.activeOperation = op
	return nil
}
func (t *fakeTransaction) Apply(_ context.Context, op Operation, _ Request) error {
	if t.f.activeOperation != op {
		return ErrState
	}
	if t.f.onApply != nil {
		t.f.onApply(op)
	}
	return t.event("apply:" + string(op))
}
func (t *fakeTransaction) Done(_ context.Context, op Operation) error {
	t.f.activeOperation = ""
	return t.event("done:" + string(op))
}
func (t *fakeTransaction) Commit(context.Context) error   { return t.event("commit") }
func (t *fakeTransaction) Rollback(context.Context) error { return t.event("rollback_owned_only") }
func (t *fakeTransaction) Close() error                   { return t.event("close") }
func installFixture() (Request, *fakeBackend) {
	return Request{Action: Install, Apply: true, AgentBinary: "/fixture/agent", AgentSHA256: strings.Repeat("1", 64), EnrollBinary: "/fixture/enroll", EnrollSHA256: strings.Repeat("2", 64), BootstrapFile: "/fixture/public.json", BootstrapSHA256: strings.Repeat("4", 64), SourceArchive: "/fixture/source.tar", SourceSHA256: strings.Repeat("3", 64)}, &fakeBackend{facts: HostFacts{Linux: true, SystemdAvailable: true, Root: true, AccountCompatible: true, InstallationOwned: false, Profile: "tls"}}
}
func TestDryRunHasNoTransactionOrEffects(t *testing.T) {
	r, f := installFixture()
	r.Apply = false
	out, e := Execute(context.Background(), r, f)
	if e != nil || out.Committed || f.begun != 0 || !reflect.DeepEqual(f.events, []string{"inspect"}) {
		t.Fatal("dry-run performed a change")
	}
}
func TestTransactionJournalAndEnrollmentBeforeStart(t *testing.T) {
	r, f := installFixture()
	out, e := Execute(context.Background(), r, f)
	if e != nil || !out.Committed || !out.IdentityRetained {
		t.Fatal("transaction failed")
	}
	joined := strings.Join(f.events, "\n")
	if strings.Index(joined, "done:"+string(OpValidate)) >= strings.Index(joined, "apply:"+string(OpStart)) {
		t.Fatal("service start before validation")
	}
	for _, op := range []Operation{OpPrepare, OpStage, OpEnroll, OpValidate, OpPublish, OpStart} {
		if strings.Index(joined, "before:"+string(op)) >= strings.Index(joined, "apply:"+string(op)) || strings.Index(joined, "apply:"+string(op)) >= strings.Index(joined, "done:"+string(op)) {
			t.Fatal("operation escaped journal")
		}
	}
}
func TestEachFailureStopsAndRollsBackOnlyOwnedChanges(t *testing.T) {
	for _, stage := range []string{"before:" + string(OpStage), "apply:" + string(OpEnroll), "done:" + string(OpPublish), "commit"} {
		t.Run(stage, func(t *testing.T) {
			r, f := installFixture()
			f.fail = stage
			out, e := Execute(context.Background(), r, f)
			if !errors.Is(e, ErrOperation) || out.Committed || !out.RolledBack || !out.IdentityRetained || strings.Contains(e.Error(), "untrusted") {
				t.Fatal("failure escaped safe rollback")
			}
			if stage == "apply:"+string(OpEnroll) && strings.Contains(strings.Join(f.events, "\n"), "apply:"+string(OpStart)) {
				t.Fatal("service started after enrollment failure")
			}
		})
	}
}
func TestCancellationNeverContinuesToServiceStart(t *testing.T) {
	r, f := installFixture()
	ctx, cancel := context.WithCancel(context.Background())
	f.onApply = func(op Operation) {
		if op == OpEnroll {
			cancel()
		}
	}
	out, e := Execute(ctx, r, f)
	if !errors.Is(e, ErrOperation) || !out.RolledBack || strings.Contains(strings.Join(f.events, "\n"), "apply:"+string(OpStart)) {
		t.Fatal("cancelled transaction continued")
	}
}
func TestUninstallNeverRequestsIdentityOrAccountDeletion(t *testing.T) {
	r, f := installFixture()
	r.Action = Uninstall
	f.facts.InstallationOwned = true
	out, e := Execute(context.Background(), r, f)
	if e != nil || !out.IdentityRetained {
		t.Fatal("uninstall failed")
	}
	for _, ev := range f.events {
		if strings.Contains(ev, "delete_identity") || strings.Contains(ev, "delete_account") || strings.Contains(ev, "enroll_as") {
			t.Fatal("uninstall expanded scope")
		}
	}
}

// This backend performs no host work; its private error must never be serialized.
type diagnosticBackend struct {
	fakeBackend
	inspectError bool
}

func (f *diagnosticBackend) Inspect(context.Context, Request) (HostFacts, error) {
	if f.inspectError {
		return f.facts, errors.New("private untrusted host detail")
	}
	return f.facts, nil
}
func (f *diagnosticBackend) Begin(context.Context, Request, Plan) (Transaction, error) {
	f.begun++
	return nil, errors.New("private untrusted begin detail")
}
func TestInstallerPreflightDiagnosticIsClosedAndNonGranting(t *testing.T) {
	for _, stage := range []Operation{"preflight_inspect", "preflight_systemd", "preflight_terminal", "preflight_systemctl_tool", "preflight_useradd_tool", "preflight_nologin_tool", "preflight_opt_directory", "preflight_etc_directory", "preflight_state_directory", "preflight_unit_directory", "preflight_unit_status", "preflight_account", "preflight_installation_state", "preflight_ownership_state", "preflight_fresh_paths", "preflight_bootstrap", "preflight_complete_profile", "preflight_artifacts", "private untrusted host detail", ""} {
		r, ordinary := installFixture()
		f := &diagnosticBackend{fakeBackend: *ordinary, inspectError: true}
		f.facts.inspectionStage = stage
		out, err := Execute(context.Background(), r, f)
		raw, _ := json.Marshal(out)
		expected := stage
		if stage == "" || stage == "private untrusted host detail" {
			expected = "preflight_inspect"
		}
		if err != ErrPreflight || out.FailureStage != expected || out.Committed || out.RolledBack || !out.IdentityRetained || f.begun != 0 || strings.Contains(string(raw), "private") {
			t.Fatal("preflight diagnostic leaked or changed effects")
		}
	}
	r, ordinary := installFixture()
	f := &diagnosticBackend{fakeBackend: *ordinary}
	bad := r
	bad.Action = "invalid"
	out, err := Execute(context.Background(), bad, f)
	if err == nil || out.FailureStage != "preflight_plan" || f.begun != 0 {
		t.Fatal("plan failure lost")
	}
	out, err = Execute(context.Background(), r, f)
	if err != ErrState || out.FailureStage != "preflight_begin" || f.begun != 1 || out.Committed || out.RolledBack {
		t.Fatal("begin failure lost or recovery invented")
	}
}
