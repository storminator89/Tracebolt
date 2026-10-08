package windowsservice

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func requireSetupDiagnostic(t *testing.T, err error, stage, category string) {
	t.Helper()
	gotStage, gotCategory := SetupDiagnostic(err)
	if gotStage != stage || gotCategory != category {
		t.Fatalf("setup metadata = %s/%s, want %s/%s", gotStage, gotCategory, stage, category)
	}
}

func TestSetupDiagnosticVocabularyIsFiniteAndPreservesCauses(t *testing.T) {
	pairs := SetupDiagnosticPairs()
	seen := make(map[[2]string]bool)
	label := regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
	for _, pair := range pairs {
		if seen[pair] || !label.MatchString(pair[0]) || !label.MatchString(pair[1]) || !SetupDiagnosticValid(pair[0], pair[1]) {
			t.Fatalf("duplicate or invalid setup vocabulary pair: %q", pair)
		}
		seen[pair] = true
		cause := &os.PathError{Op: "read", Path: `C:\private\invitation-secret`, Err: ErrUnsafePath}
		marked := setupStageError(pair[0], pair[1], cause)
		requireSetupDiagnostic(t, marked, pair[0], pair[1])
		requireSetupDiagnostic(t, fmt.Errorf("private wrapper: %w", marked), pair[0], pair[1])
		if marked.Error() != cause.Error() || !errors.Is(marked, ErrUnsafePath) || Describe(marked) != Describe(cause) {
			t.Fatal("setup metadata changed Error, sentinel, or legacy diagnostic behavior")
		}
		var pathErr *os.PathError
		if !errors.As(marked, &pathErr) || pathErr != cause {
			t.Fatal("setup metadata lost errors.As identity")
		}
		if fmt.Sprintf("%#v", marked) != cause.Error() || fmt.Sprintf("%+v", marked) != cause.Error() {
			t.Fatal("reflection formatting changed Error rendering or exposed private fields")
		}
		if got := setupStageError(pair[0], pair[1], nil); got != nil {
			t.Fatal("nil error became a failure")
		}
	}
	if !seen[[2]string{"unknown", "unknown"}] {
		t.Fatal("missing unknown vocabulary pair")
	}
	pairs[0] = [2]string{"secret", "secret"}
	if SetupDiagnosticPairs()[0] != [2]string{"unknown", "unknown"} {
		t.Fatal("public vocabulary slice can modify internal labels")
	}
	// Independently valid labels must not admit an unregistered pair.
	if SetupDiagnosticValid("service_plan_context", "unsafe_path") {
		t.Fatal("vocabulary accepted a Cartesian-product combination")
	}
}

func TestSetupDiagnosticNeverFormatsHostileErrors(t *testing.T) {
	cause := &hostileDiagnosticCause{}
	marked := setupStageError("service_trust_root", "open_failed", cause)
	requireSetupDiagnostic(t, marked, "service_trust_root", "open_failed")
	outer := setupStageError("service_plan_executable", "failed", marked)
	requireSetupDiagnostic(t, outer, "service_trust_root", "open_failed")
	requireSetupDiagnostic(t, joinWithoutFormatting{nil, marked}, "service_trust_root", "open_failed")
	for _, err := range []error{nil, cause, &hostileUnwrapper{}, &cyclicDiagnosticCause{}, (*setupDiagnosticError)(nil),
		&setupDiagnosticError{stage: maliciousDiagnosticText, category: "failed", cause: cause},
		setupStageError("service_plan_context", maliciousDiagnosticText, cause),
	} {
		requireSetupDiagnostic(t, err, "unknown", "unknown")
	}
	var deep error = marked
	for range 128 {
		deep = joinWithoutFormatting{deep}
	}
	requireSetupDiagnostic(t, deep, "unknown", "unknown")
	wide := make(joinWithoutFormatting, 10000)
	wide[len(wide)-1] = marked
	requireSetupDiagnostic(t, wide, "unknown", "unknown")
}

// These callbacks alter only portable fixture behavior. They never access SCM,
// native filesystem policy, randomness, credentials or an installed service.
type setupFaultBackend struct {
	*fakeBackend
	layoutErr, verifyErr error
	verifyHook           func()
	createHook           func(Configuration) (service, error)
	lookupSID            string
}

func (b *setupFaultBackend) Layout() (Layout, error) { return b.layout, b.layoutErr }
func (b *setupFaultBackend) VerifyExecutable(l Layout) (string, error) {
	if b.verifyHook != nil {
		b.verifyHook()
	}
	if b.verifyErr != nil {
		return "", b.verifyErr
	}
	return b.fakeBackend.VerifyExecutable(l)
}
func (b *setupFaultBackend) Create(c Configuration) (service, error) {
	if b.createHook != nil {
		b.created++
		return b.createHook(c)
	}
	return b.fakeBackend.Create(c)
}
func (b *setupFaultBackend) LookupSID() (string, error) {
	if b.lookupSID != "" {
		return b.lookupSID, nil
	}
	return b.fakeBackend.LookupSID()
}

func TestSetupPlanFailureSites(t *testing.T) {
	fault := errors.New("private native failure with a path and code")
	for _, tc := range []struct {
		name, stage, category string
		change                func(*setupFaultBackend, context.CancelFunc)
	}{
		{"context", "service_plan_context", "interrupted", func(_ *setupFaultBackend, cancel context.CancelFunc) { cancel() }},
		{"layout", "service_plan_layout", "failed", func(b *setupFaultBackend, _ context.CancelFunc) { b.layoutErr = fault }},
		{"executable", "service_plan_executable", "failed", func(b *setupFaultBackend, _ context.CancelFunc) { b.verifyErr = fault }},
		{"inspect_context", "service_inspect_context", "interrupted", func(b *setupFaultBackend, cancel context.CancelFunc) { b.verifyHook = cancel }},
		{"inspect_open", "service_inspect_open", "failed", func(b *setupFaultBackend, _ context.CancelFunc) { b.errorOpen = fault }},
		{"inspect_snapshot", "service_inspect_snapshot", "failed", func(b *setupFaultBackend, _ context.CancelFunc) { b.s = &fakeService{inspectError: fault} }},
		{"nested_native", "service_trust_directory", "case_failed", func(b *setupFaultBackend, _ context.CancelFunc) {
			b.verifyErr = setupStageError("service_trust_directory", "case_failed", ErrUnsafePath)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &setupFaultBackend{fakeBackend: fixtureBackend(t)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.change(b, cancel)
			_, err := plan(ctx, b)
			requireSetupDiagnostic(t, err, tc.stage, tc.category)
			if b.created != 0 {
				t.Fatal("failed plan mutated service")
			}
		})
	}
}

func TestSetupInstallFailureSites(t *testing.T) {
	fault := errors.New("private installation error")
	for _, tc := range []struct {
		name, stage, category string
		change                func(*setupFaultBackend, *InstallPlan, context.CancelFunc)
		created               bool
	}{
		{"context", "service_install_context", "interrupted", func(_ *setupFaultBackend, _ *InstallPlan, cancel context.CancelFunc) { cancel() }, false},
		{"layout", "service_install_layout", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.layoutErr = fault }, false},
		{"plan", "service_install_plan", "mismatch", func(_ *setupFaultBackend, p *InstallPlan, _ context.CancelFunc) { p.InstallationID = "bad" }, false},
		{"plan_existing", "service_install_plan_existing", "existing", func(_ *setupFaultBackend, p *InstallPlan, _ context.CancelFunc) { p.Existing.Exists = true }, false},
		{"inspect", "service_inspect_open", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.errorOpen = fault }, false},
		{"current_existing", "service_install_current_existing", "existing", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) {
			b.s = &fakeService{snapshot: Snapshot{Exists: true}}
		}, false},
		{"executable", "service_install_executable", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.verifyErr = fault }, false},
		{"hash", "service_install_hash", "changed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.hash = strings.Repeat("b", 64) }, false},
		{"precreate_context", "service_install_precreate_context", "interrupted", func(b *setupFaultBackend, _ *InstallPlan, cancel context.CancelFunc) { b.verifyHook = cancel }, false},
		{"create", "service_install_create", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.createErr = fault }, true},
		{"handle", "service_install_handle", "missing", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) {
			b.createHook = func(Configuration) (service, error) { return nil, nil }
		}, true},
		{"sid", "service_install_sid", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.lookupErr = fault }, true},
		{"sid_invalid", "service_install_sid", "invalid", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) { b.lookupSID = "bad" }, true},
		{"snapshot", "service_install_snapshot", "failed", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) {
			b.createHook = func(Configuration) (service, error) { return &fakeService{inspectError: fault}, nil }
		}, true},
		{"snapshot_mismatch", "service_install_snapshot", "mismatch", func(b *setupFaultBackend, _ *InstallPlan, _ context.CancelFunc) {
			b.createHook = func(Configuration) (service, error) { return &fakeService{}, nil }
		}, true},
	} {
		for _, staged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/staged=%t", tc.name, staged), func(t *testing.T) {
				b := &setupFaultBackend{fakeBackend: fixtureBackend(t)}
				p, err := plan(context.Background(), b)
				if err != nil {
					t.Fatal(err)
				}
				if staged {
					p.Configuration.StartType = 4
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tc.change(b, &p, cancel)
				r, err := installMode(ctx, b, p, staged)
				requireSetupDiagnostic(t, err, tc.stage, tc.category)
				if r.Complete || (b.created != 0) != tc.created {
					t.Fatal("failure changed creation boundary")
				}
				if tc.created && r.InstallationID != p.InstallationID {
					t.Fatal("lost partial receipt")
				}
				if b.s != nil && (b.s.deletes != 0 || b.s.starts != 0 || b.s.stops != 0) {
					t.Fatal("failure triggered cleanup mutation")
				}
			})
		}
	}
}

func TestSetupOwnedFailureSites(t *testing.T) {
	fault := errors.New("private owned-service error")
	for _, tc := range []struct {
		name, stage, category string
		change                func(*setupFaultBackend, *Receipt, context.CancelFunc)
		opened                bool
	}{
		{"context", "service_owned_context", "interrupted", func(_ *setupFaultBackend, _ *Receipt, cancel context.CancelFunc) { cancel() }, false},
		{"layout", "service_owned_layout", "failed", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.layoutErr = fault }, false},
		{"receipt", "service_owned_receipt", "mismatch", func(_ *setupFaultBackend, r *Receipt, _ context.CancelFunc) { r.Complete = false }, false},
		{"open", "service_owned_open", "failed", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.errorOpen = fault }, false},
		{"inspect", "service_owned_inspect", "failed", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.s.inspectError = fault }, true},
		{"binding", "service_owned_binding", "mismatch", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.s.snapshot.ServiceSID = "bad" }, true},
		{"executable", "service_owned_executable", "failed", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.verifyErr = fault }, true},
		{"hash", "service_owned_hash", "changed", func(b *setupFaultBackend, _ *Receipt, _ context.CancelFunc) { b.hash = strings.Repeat("b", 64) }, true},
		{"final_context", "service_owned_final_context", "interrupted", func(b *setupFaultBackend, _ *Receipt, cancel context.CancelFunc) { b.verifyHook = cancel }, true},
	} {
		for _, staged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/staged=%t", tc.name, staged), func(t *testing.T) {
				base, r := installedFixture(t)
				b := &setupFaultBackend{fakeBackend: base}
				if staged {
					r.Version = 2
					b.s.snapshot.Configuration.StartType = 4
					r.ConfigurationSHA256 = digestConfig(b.s.snapshot.Configuration)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tc.change(b, &r, cancel)
				closes := b.s.closes
				s, _, err := openOwnedMode(ctx, b, r, readAccess, true, staged)
				requireSetupDiagnostic(t, err, tc.stage, tc.category)
				if s != nil || (b.s.closes != closes) != tc.opened {
					t.Fatal("failed owned-check leaked or unexpectedly closed a handle")
				}
				if b.s.starts != 0 || b.s.stops != 0 || b.s.deletes != 0 {
					t.Fatal("failed owned-check mutated service")
				}
			})
		}
	}
}

// Source-only audit makes all Windows return-site metadata testable on portable
// CI. This validates declared labels and forwarding; it does not execute native
// calls or prove Windows acceptance.
func TestSetupDiagnosticSourceLabelsAreRegistered(t *testing.T) {
	for _, path := range []string{"service.go", "native_windows.go", "trust_windows.go", "setup_diagnostics.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "setupStageError" {
				return true
			}
			stage, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				t.Fatal("nonliteral setup stage")
			}
			category, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				return true
			} // finite role/query helper cases checked separately
			s, _ := strconv.Unquote(stage.Value)
			c, _ := strconv.Unquote(category.Value)
			if !SetupDiagnosticValid(s, c) {
				t.Errorf("unregistered source pair %s/%s", s, c)
			}
			return true
		})
	}
	for _, stage := range []string{"service_query_privileges", "service_query_failure_actions", "service_query_triggers"} {
		for _, category := range []string{"probe_invalid", "probe_failed", "size_invalid", "read_failed", "result_invalid"} {
			if !SetupDiagnosticValid(stage, category) {
				t.Fatalf("unregistered query substep %s/%s", stage, category)
			}
		}
	}
	for _, stage := range []string{"service_trust_root", "service_trust_directory", "service_trust_file"} {
		for _, category := range []string{"open_failed", "info_failed", "reparse", "type_invalid", "final_failed", "final_size", "final_mismatch", "case_failed", "case_enabled"} {
			want := stage != "service_trust_file" || !strings.HasPrefix(category, "case_")
			if SetupDiagnosticValid(stage, category) != want {
				t.Fatalf("incorrect path-role pair %s/%s", stage, category)
			}
		}
	}
}

func TestSetupCreatePrefixAndSafeNestedRendering(t *testing.T) {
	cause := &os.PathError{Op: "read", Path: "private-secret", Err: ErrUnsafePath}
	native := setupStageError("service_create_privileges", "failed", cause)
	err := setupStageError("service_install_create", "failed", fmt.Errorf("service creation/configuration incomplete; retain installation intent and inspect: %w", native))
	want := "service creation/configuration incomplete; retain installation intent and inspect: " + cause.Error()
	if err.Error() != want || !errors.Is(err, ErrUnsafePath) {
		t.Fatal("changed existing creation error")
	}
	requireSetupDiagnostic(t, err, "service_create_privileges", "failed")
	if fmt.Sprintf("%#v", err) != want {
		t.Fatal("reflection exposed nested cause fields or changed Error rendering")
	}
}

func TestSetupDiagnosticPreservesEveryLegacyReason(t *testing.T) {
	for _, cause := range []error{ErrUnsupported, ErrUnsafeIdentity, ErrRuntimeReadAccess, ErrUnsafePath, ErrMismatch, ErrNotInstalled, ErrExisting, ErrNotStopped, context.Canceled, context.DeadlineExceeded} {
		err := setupStageError("service_plan_executable", "failed", cause)
		if Describe(err) != Describe(cause) || !errors.Is(err, cause) || err.Error() != cause.Error() {
			t.Fatal("setup metadata changed a legacy reason or sentinel")
		}
		marked := Mark(PhaseSetup, ReasonOperationFailed, err)
		requireSetupDiagnostic(t, marked, "service_plan_executable", "failed")
		if Describe(marked) != Describe(Mark(PhaseSetup, ReasonOperationFailed, cause)) {
			t.Fatal("setup metadata changed an explicit legacy reason")
		}
	}
}
