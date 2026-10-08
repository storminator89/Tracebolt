package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func assertSetupDiagnosis(t *testing.T, err error, wantStage, wantCategory string) {
	t.Helper()
	stage, category := setupFailureDiagnostic(err)
	if stage != wantStage || category != wantCategory {
		t.Fatalf("diagnosis = %s/%s, want %s/%s", stage, category, wantStage, wantCategory)
	}
	if code := freshChildFailureCode(err); code <= 1 {
		t.Fatalf("diagnosis has no finite exit code: %s/%s", stage, category)
	} else {
		ds, dc := freshgate.DecodeChildFailureExit(uint32(code))
		if ds != stage || dc != category {
			t.Fatal("finite decode mismatch")
		}
	}
}
func TestSetupDiagnosticEveryInjectedStage(t *testing.T) {
	for step, stage := range map[string]string{"plan": "service_plan", "read-bootstrap": "bootstrap_read", "validate-bootstrap": "bootstrap_validate", "create-journal": "journal_create", "intent.json": "intent_write", "apply": "service_install", "receipt.json": "receipt_write", "prepare": "runtime_prepare", "prepared-receipt": "prepared_receipt_write", "close": "journal_close", "preclaim": "owned_verify", "enroll": "enrollment", "start": "service_start"} {
		t.Run(step, func(t *testing.T) {
			f := &setupFixture{fail: step}
			_, err := setup(context.Background(), "fixture", f.operations())
			assertSetupDiagnosis(t, err, stage, "failed")
		})
	}
	f := &setupFixture{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := setup(ctx, "fixture", f.operations())
	assertSetupDiagnosis(t, err, "setup_context", "interrupted")
	_, err = setup(nil, "fixture", f.operations())
	assertSetupDiagnosis(t, err, "setup_validate", "failed")
}
func TestReadSetupDiagnosticEveryInjectedStage(t *testing.T) {
	for step, stage := range map[string]string{"plan": "fresh_plan", "bootstrap": "bootstrap_read", "validate": "bootstrap_validate", "journal": "journal_create", "write-intent.json": "intent_write", "install-disabled": "service_install", "write-receipt.json": "receipt_write", "fresh-scopes": "scopes_absent", "prepare": "runtime_prepare", "close": "journal_close", "verify-disabled": "owned_verify", "claim-started": "claim_record", "claim": "enrollment", "activation-started": "activation_record", "activate-identity": "identity_activate", "identity": "identity_read", "grants-started": "grants_record", "configure": "grants_configure", "verify-grants": "grants_verify", "grant-digests": "grants_digests", "grants-verified": "grants_verified_record", "startup-transition-started": "startup_record", "activate-startup": "startup_activate", "configured": "configured_record", "start": "service_start"} {
		t.Run(step, func(t *testing.T) {
			f := &readSetupFixture{fail: step}
			_, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks())
			assertSetupDiagnosis(t, err, stage, "failed")
		})
	}
}
func TestReadSetupJournalPreservesOriginalPublicErrorAndCategory(t *testing.T) {
	f := &readSetupFixture{}
	h := f.hooks()
	h.setup.createJournal = func(windowsservice.Layout) (setupJournal, error) { return nil, windowsstate.ErrPolicy }
	_, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h)
	assertSetupDiagnosis(t, err, "journal_create", "state_policy")
	if errors.Is(err, windowsstate.ErrPolicy) || !errors.Is(err, errLifecycle) {
		t.Fatal("previous public error boundary changed")
	}
}
func TestSetupMetadataPreservesErrorIdentityRenderingAndInnerStage(t *testing.T) {
	cause := errors.New("fixture error")
	err := setupFailed("runtime_root_open", cause)
	if err.Error() != cause.Error() || !errors.Is(err, cause) {
		t.Fatal("error identity changed")
	}
	var target *setupFailure
	if !errors.As(err, &target) || target.cause != cause {
		t.Fatal("unwrap contract lost")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		want := cause.Error()
		if format == "%q" {
			want = fmt.Sprintf("%q", want)
		}
		if got := fmt.Sprintf(format, err); got != want {
			t.Fatal("wrapper rendering exposed fields", got)
		}
	}
	outer := setupFailed("coordinator", err)
	assertSetupDiagnosis(t, outer, "runtime_root_open", "failed")
}

type panicSetupDiagnostic struct{}

func (panicSetupDiagnostic) Error() string { panic("private error invoked") }
func (panicSetupDiagnostic) Unwrap() error { panic("private unwrap invoked") }

type cycleSetupDiagnostic struct{}

func (c *cycleSetupDiagnostic) Error() string { panic("private error invoked") }
func (c *cycleSetupDiagnostic) Unwrap() error { return c }

type wideSetupDiagnostic struct{ children []error }

func (w wideSetupDiagnostic) Error() string   { panic("private error invoked") }
func (w wideSetupDiagnostic) Unwrap() []error { return w.children }
func TestSetupDiagnosticUnknownPanicCycleAndWideChainsFailClosed(t *testing.T) {
	wide := make([]error, 10000)
	for i := range wide {
		wide[i] = errors.New("private")
	}
	for _, err := range []error{errors.New("private"), panicSetupDiagnostic{}, &cycleSetupDiagnostic{}, wideSetupDiagnostic{wide}} {
		if s, c := setupFailureDiagnostic(err); s != "unknown" || c != "unknown" {
			t.Fatal("untrusted diagnostic admitted")
		}
		if setupCauseCategory(err) != "failed" || freshChildFailureCode(err) != 1 {
			t.Fatal("untrusted cause admitted")
		}
	}
	if freshChildFailureCode(nil) != 0 {
		t.Fatal("nil result not success")
	}
	for _, pair := range [][2]string{{"private", "failed"}, {"bootstrap_read", "private"}, {"unknown", "failed"}} {
		if freshChildFailureCode(setupFailedCategory(pair[0], pair[1], errors.New("private"))) != 1 {
			t.Fatal("unreviewed pair admitted")
		}
	}
}
func TestSetupCauseCategoriesAreIdentityBasedAndFinite(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "interrupted"}, {context.DeadlineExceeded, "interrupted"}, {os.ErrPermission, "access_denied"}, {os.ErrNotExist, "not_found"},
		{windowsstate.ErrUnsupported, "unsupported"}, {windowsstate.ErrPolicy, "state_policy"}, {windowsstate.ErrIntegrity, "state_integrity"}, {windowsstate.ErrStorage, "state_storage"}, {windowsstate.ErrPoisoned, "state_poisoned"}, {windowsstate.ErrClosed, "state_closed"},
		{enrollmentclient.ErrBootstrap, "enrollment_bootstrap"}, {enrollmentclient.ErrState, "enrollment_state"}, {enrollmentclient.ErrLocked, "enrollment_locked"}, {enrollmentclient.ErrResponse, "enrollment_response"}, {enrollmentclient.ErrTransport, "enrollment_transport"}, {enrollmentclient.ErrInvitation, "enrollment_invitation"}, {enrollmentclient.ErrTerminal, "enrollment_terminal"}, {enrollmentclient.ErrInput, "enrollment_input"}, {enrollmentclient.ErrServiceDeadline, "enrollment_deadline"},
	} {
		if setupCauseCategory(fmt.Errorf("private wrapper: %w", tc.err)) != tc.want {
			t.Fatal("known cause lost")
		}
		if setupCauseCategory(errors.New(tc.err.Error())) != "failed" {
			t.Fatal("text used as authority")
		}
	}
}

// The canceled public installer guard returns before Layout or any backend
// method. This produces genuine service metadata without a native operation.
func inertInstallFailure(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receipt, err := windowsservice.ApplyFreshReadSetup(ctx, windowsservice.InstallPlan{})
	if receipt != (windowsservice.Receipt{}) {
		t.Fatal("canceled installer returned receipt")
	}
	if s, c := windowsservice.SetupDiagnostic(err); s != "service_install_context" || c != "interrupted" {
		t.Fatal("inert installer guard changed")
	}
	return err
}
func TestReadSetupFirstInstallFailureSurvivesRejectedReceipt(t *testing.T) {
	first := inertInstallFailure(t)
	f := &readSetupFixture{}
	h := f.hooks()
	h.setup.apply = func(context.Context, windowsservice.InstallPlan) (windowsservice.Receipt, error) {
		_ = f.call("apply-failed")
		return windowsservice.Receipt{}, first
	}
	_, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h)
	assertSetupDiagnosis(t, err, "service_install_context", "interrupted")
	historical := marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, errLifecycle)
	if err.Error() != historical.Error() || !errors.Is(err, errLifecycle) || errors.Is(err, context.Canceled) {
		t.Fatal("historical receipt error changed")
	}
	want := []string{"plan", "bootstrap", "validate", "journal", "write-intent.json", "apply-failed", "close"}
	if !reflect.DeepEqual(f.steps, want) || f.started != 0 || f.configured != 0 || f.transitioned != 0 {
		t.Fatal("compound fault changed side effects", f.steps)
	}
}
func TestSetupFirstInstallFailureStillAttemptsReceiptWrite(t *testing.T) {
	first := inertInstallFailure(t)
	f := &setupFixture{fail: "receipt.json"}
	h := f.operations()
	h.apply = func(context.Context, windowsservice.InstallPlan) (windowsservice.Receipt, error) {
		_ = f.call("apply-failed")
		return windowsservice.Receipt{}, first
	}
	_, err := setup(context.Background(), "fixture", h)
	assertSetupDiagnosis(t, err, "service_install_context", "interrupted")
	if f.receiptWrites != 1 {
		t.Fatal("mandatory receipt write skipped")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("first native cause replaced historical receipt cause")
	}
	if d := windowsservice.Diagnostic(err); d.Phase != windowsservice.PhaseReceipt || d.Reason != windowsservice.ReasonStateRejected {
		t.Fatal("historical public receipt diagnosis changed")
	}
	for _, step := range f.steps {
		if step == "prepare" || step == "enroll" || step == "start" {
			t.Fatal("failed install advanced")
		}
	}
}

func TestSetupFirstFailureMetadataDoesNotAdoptSecondaryNativeCause(t *testing.T) {
	secondary := inertInstallFailure(t)
	retained := setupFirstInstallFailure(errors.New("private first failure"), secondary)
	if code := freshChildFailureCode(retained); code != freshgate.ChildFailureExitCode("service_install", "failed") {
		t.Fatal("secondary failure displaced first metadata")
	}
	if retained.Error() != secondary.Error() || !errors.Is(retained, context.Canceled) {
		t.Fatal("secondary public cause was changed")
	}
	if setupFirstInstallFailure(nil, secondary) != secondary {
		t.Fatal("nil first failure changed result")
	}
}

func TestRetainedBootstrapValidationCapturesCategoryBeforePublicCollapse(t *testing.T) {
	// Production bootstrap deliberately returns errLifecycle instead of the parse
	// error. Capture only its finite category before retaining that same boundary.
	returned := setupFailedCategory("bootstrap_retained_validate", setupCauseCategory(enrollmentclient.ErrBootstrap), marked(windowsservice.PhaseBootstrap, windowsservice.ReasonStateUnavailable, errLifecycle))
	assertSetupDiagnosis(t, returned, "bootstrap_retained_validate", "enrollment_bootstrap")
	if errors.Is(returned, enrollmentclient.ErrBootstrap) || !errors.Is(returned, errLifecycle) {
		t.Fatal("bootstrap public error boundary changed")
	}
}

func TestWriteFailureStagesUseFixedFiniteCategory(t *testing.T) {
	for _, stage := range []string{"fresh_disclosure", "success_write"} {
		for _, cause := range []error{os.ErrPermission, os.ErrNotExist, context.Canceled, windowsstate.ErrPolicy, errors.New("private writer detail")} {
			returned := setupFailedCategory(stage, "failed", cause)
			assertSetupDiagnosis(t, returned, stage, "failed")
			if !errors.Is(returned, cause) || returned.Error() != cause.Error() {
				t.Fatal("writer public error changed")
			}
		}
	}
}

func TestReadSetupStartupPermissionFailureCategories(t *testing.T) {
	for _, stage := range []string{"startup_activate", "service_start"} {
		f := &readSetupFixture{}
		h := f.hooks()
		if stage == "startup_activate" {
			h.activateStartup = func(context.Context, windowsservice.Receipt) (windowsservice.Receipt, error) {
				return windowsservice.Receipt{}, os.ErrPermission
			}
		} else {
			h.setup.start = func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				return windowsservice.ApplyResult{}, os.ErrPermission
			}
		}
		_, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h)
		assertSetupDiagnosis(t, err, stage, "access_denied")
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal("native permission cause changed")
		}
	}
}
