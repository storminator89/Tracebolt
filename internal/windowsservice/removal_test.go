package windowsservice

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

var removalSIDUnavailable = errors.New("service SID lookup unavailable after deletion")

// These fixtures model a successful DeleteService followed by a still-queryable
// stopped object whose account name no longer resolves. They never access SCM.
type removalTestService struct {
	*fakeService
	ordinaryReads, removalReads, handles int
	sidUnavailable                       bool
	queryErr, closeErr                   error
	queryHook, closeHook                 func()
}

func (s *removalTestService) Inspect() (Snapshot, error) {
	s.ordinaryReads++
	if s.sidUnavailable {
		return Snapshot{}, removalSIDUnavailable
	}
	return s.fakeService.Inspect()
}
func (s *removalTestService) inspectRemoval() (Snapshot, error) {
	s.removalReads++
	if s.queryHook != nil {
		s.queryHook()
	}
	snapshot := s.snapshot
	snapshot.ServiceSID = ""
	return snapshot, s.queryErr
}
func (s *removalTestService) Delete() error {
	err := s.fakeService.Delete()
	if err == nil {
		s.sidUnavailable = true
	}
	return err
}
func (s *removalTestService) Close() error {
	s.handles--
	s.fakeService.Close()
	if s.closeHook != nil {
		s.closeHook()
	}
	return s.closeErr
}

type removalTestBackend struct {
	*fakeBackend
	service                *removalTestService
	absent                 bool
	lookups, layouts       int
	layoutErr              error
	layoutHook, openHook   func()
	verifyHook             func()
	verifyErr              error
	serviceWithoutObserver bool
}

func (b *removalTestBackend) Layout() (Layout, error) {
	b.layouts++
	if b.layoutHook != nil {
		b.layoutHook()
	}
	return b.layout, b.layoutErr
}
func (b *removalTestBackend) Open(a access) (service, error) {
	b.opened = append(b.opened, a)
	if b.openHook != nil {
		b.openHook()
	}
	if b.errorOpen != nil {
		return nil, b.errorOpen
	}
	if b.absent {
		return nil, fmt.Errorf("open: %w", ErrNotInstalled)
	}
	if b.serviceWithoutObserver {
		return b.s, nil
	}
	b.service.handles++
	return b.service, nil
}
func (b *removalTestBackend) LookupSID() (string, error) {
	b.lookups++
	if b.service.sidUnavailable {
		return "", removalSIDUnavailable
	}
	return b.fakeBackend.LookupSID()
}
func (b *removalTestBackend) VerifyExecutable(l Layout) (string, error) {
	if b.verifyHook != nil {
		b.verifyHook()
	}
	if b.verifyErr != nil {
		b.verified++
		return "", b.verifyErr
	}
	return b.fakeBackend.VerifyExecutable(l)
}

func removalFixture(t *testing.T) (*removalTestBackend, Receipt) {
	t.Helper()
	b, r := installedFixture(t)
	b.opened = nil
	b.verified = 0
	b.s.closes = 0
	return &removalTestBackend{fakeBackend: b, service: &removalTestService{fakeService: b.s}}, r
}

func requireRemovalReadOnly(t *testing.T, b *removalTestBackend) {
	t.Helper()
	if b.created != 1 || b.lookups != 0 || b.s.starts != 0 || b.s.stops != 0 || b.s.deletes != 0 || b.service.ordinaryReads != 0 || b.service.handles != 0 {
		t.Fatalf("observation mutated, resolved identity, or retained handle: %+v / %+v", b, b.service)
	}
	for _, a := range b.opened {
		if a != readAccess {
			t.Fatalf("observation requested non-query access: %d", a)
		}
	}
}

func TestInspectRemovalSurvivesSIDLossOnlyAfterStrictDelete(t *testing.T) {
	b, r := removalFixture(t)
	deleted, err := apply(context.Background(), b, r, deleteAccess)
	if err != nil || !deleted.Requested || !deleted.DeletePending || b.s.deletes != 1 || b.service.ordinaryReads != 1 || b.service.handles != 0 {
		t.Fatalf("strict delete failed: %+v, %v", deleted, err)
	}
	if !reflect.DeepEqual(b.opened, []access{deleteAccess}) {
		t.Fatalf("unexpected deletion access: %v", b.opened)
	}
	// Ordinary inspection, ownership checks and mutation continue to require the
	// native SID lookup. Only the new post-delete observer can read without it.
	if _, err := inspect(context.Background(), b); !errors.Is(err, removalSIDUnavailable) {
		t.Fatalf("ordinary inspection bypassed SID resolution: %v", err)
	}
	if _, err := inspectOwned(context.Background(), b, r); !errors.Is(err, removalSIDUnavailable) {
		t.Fatalf("owned inspection bypassed SID resolution: %v", err)
	}
	if _, err := apply(context.Background(), b, r, deleteAccess); !errors.Is(err, removalSIDUnavailable) || b.s.deletes != 1 {
		t.Fatalf("another deletion bypassed SID resolution: %v", err)
	}
	ordinaryReads, closes := b.service.ordinaryReads, b.s.closes
	b.opened = nil
	for range 2 {
		got, err := inspectRemoval(context.Background(), b, r)
		if err != nil || !got.Exists || got.State != Stopped || got.ServiceSID != "" || !reflect.DeepEqual(got.Configuration, b.s.snapshot.Configuration) {
			t.Fatalf("still-present observation failed: %+v, %v", got, err)
		}
		if b.service.handles != 0 {
			t.Fatal("observation retained a handle that can delay removal")
		}
	}
	b.absent = true
	got, err := inspectRemoval(context.Background(), b, r)
	if err != nil || got.Exists || b.s.closes != closes+2 || b.service.removalReads != 2 || b.service.ordinaryReads != ordinaryReads || b.lookups != 0 || b.verified != 2 || b.s.deletes != 1 {
		t.Fatalf("invalid absence observation or repeated mutation: %+v, %v", got, err)
	}
	if !reflect.DeepEqual(b.opened, []access{readAccess, readAccess, readAccess}) {
		t.Fatalf("removal observation requested mutating access: %v", b.opened)
	}
}

func TestInspectRemovalRejectsCorruptReceiptBeforeOpen(t *testing.T) {
	changes := map[string]func(*Receipt){
		"incomplete":            func(r *Receipt) { r.Complete = false },
		"unsupported version":   func(r *Receipt) { r.Version = 2 },
		"program files":         func(r *Receipt) { r.Layout.ProgramFiles = `C:\Program Files` },
		"program data":          func(r *Receipt) { r.Layout.ProgramData = `C:\ProgramData` },
		"executable path":       func(r *Receipt) { r.Layout.Executable += ".other" },
		"state root":            func(r *Receipt) { r.Layout.StateRoot += `\other` },
		"enrollment root":       func(r *Receipt) { r.Layout.EnrollmentRoot += `\other` },
		"sender root":           func(r *Receipt) { r.Layout.SenderRoot += `\other` },
		"missing ID":            func(r *Receipt) { r.InstallationID = "" },
		"malformed ID":          func(r *Receipt) { r.InstallationID = strings.Repeat("z", 32) },
		"uppercase ID":          func(r *Receipt) { r.InstallationID = strings.Repeat("A", 32) },
		"unbound ID":            func(r *Receipt) { r.InstallationID = strings.Repeat("f", 32) },
		"missing executable":    func(r *Receipt) { r.ExecutableSHA256 = "" },
		"uppercase executable":  func(r *Receipt) { r.ExecutableSHA256 = strings.Repeat("A", 64) },
		"unbound executable":    func(r *Receipt) { r.ExecutableSHA256 = strings.Repeat("f", 64) },
		"missing config digest": func(r *Receipt) { r.ConfigurationSHA256 = "" },
		"wrong config digest":   func(r *Receipt) { r.ConfigurationSHA256 = fixtureHash },
		"missing SID":           func(r *Receipt) { r.ServiceSID = "" },
		"non-service SID":       func(r *Receipt) { r.ServiceSID = LocalServiceSID },
		"malformed service SID": func(r *Receipt) { r.ServiceSID = "S-1-5-80-1-2-3-4-4294967296" },
	}
	for name, change := range changes {
		for _, absent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/absent=%t", name, absent), func(t *testing.T) {
				b, r := removalFixture(t)
				b.absent = absent
				change(&r)
				got, err := inspectRemoval(context.Background(), b, r)
				if !errors.Is(err, ErrMismatch) || got.Exists || len(b.opened) != 0 || b.s.closes != 0 || b.service.removalReads != 0 || b.verified != 0 {
					t.Fatalf("corrupt receipt admitted: %+v, %v", got, err)
				}
				requireSetupDiagnostic(t, err, "service_removal_receipt", "mismatch")
				requireRemovalReadOnly(t, b)
			})
		}
	}
}

func TestInspectRemovalRequiresEveryConfigurationField(t *testing.T) {
	changes := map[string]func(*Configuration){
		"name":                func(c *Configuration) { c.Name = "foreign" },
		"display name":        func(c *Configuration) { c.DisplayName = "foreign" },
		"binary":              func(c *Configuration) { c.BinaryPath += ` "--other"` },
		"account":             func(c *Configuration) { c.Account = "LocalSystem" },
		"service type":        func(c *Configuration) { c.ServiceType = 32 },
		"start type":          func(c *Configuration) { c.StartType = 4 },
		"error control":       func(c *Configuration) { c.ErrorControl = 0 },
		"SID type":            func(c *Configuration) { c.SIDType = 0 },
		"required privileges": func(c *Configuration) { c.RequiredPrivileges = []string{"SeDebugPrivilege"} },
		"dependencies":        func(c *Configuration) { c.Dependencies = []string{"foreign"} },
		"load order group":    func(c *Configuration) { c.LoadOrderGroup = "foreign" },
		"delayed startup":     func(c *Configuration) { c.DelayedAutoStart = true },
		"failure actions":     func(c *Configuration) { c.FailureActions = true },
		"triggers":            func(c *Configuration) { c.Triggers = true },
		"missing marker":      func(c *Configuration) { c.Description = "" },
		"foreign marker":      func(c *Configuration) { c.Description += "foreign" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b, r := removalFixture(t)
			change(&b.s.snapshot.Configuration)
			got, err := inspectRemoval(context.Background(), b, r)
			if !errors.Is(err, ErrMismatch) || got.Exists || b.s.closes != 1 || b.service.removalReads != 1 {
				t.Fatalf("changed configuration admitted: %+v, %v", got, err)
			}
			requireSetupDiagnostic(t, err, "service_removal_binding", "mismatch")
			requireRemovalReadOnly(t, b)
		})
	}
}

func TestInspectRemovalRequiresStoppedState(t *testing.T) {
	for _, state := range []State{0, StartPending, StopPending, Running, 5, 6, 7, 999} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			b, r := removalFixture(t)
			b.s.snapshot.State = state
			got, err := inspectRemoval(context.Background(), b, r)
			if !errors.Is(err, ErrNotStopped) || got.Exists || b.s.closes != 1 {
				t.Fatalf("nonstopped state admitted: %+v, %v", got, err)
			}
			requireSetupDiagnostic(t, err, "service_removal_state", "not_stopped")
			requireRemovalReadOnly(t, b)
		})
	}
}

func TestInspectRemovalOnlyOpenAbsenceCompletes(t *testing.T) {
	fault := errors.New("injected observation failure")
	for _, tc := range []struct {
		name, stage, category string
		change                func(*removalTestBackend)
		cause                 error
		closes                int
	}{
		{"absent", "", "", func(b *removalTestBackend) { b.absent = true }, nil, 0},
		{"layout", "service_removal_layout", "failed", func(b *removalTestBackend) { b.layoutErr = fault }, fault, 0},
		{"access denied", "service_removal_open", "failed", func(b *removalTestBackend) { b.errorOpen = syscall.Errno(5) }, syscall.Errno(5), 0},
		{"invalid handle", "service_removal_open", "failed", func(b *removalTestBackend) { b.errorOpen = syscall.Errno(6) }, syscall.Errno(6), 0},
		{"marked for deletion", "service_removal_open", "failed", func(b *removalTestBackend) { b.errorOpen = syscall.Errno(1072) }, syscall.Errno(1072), 0},
		{"ambiguous absence", "service_removal_open", "failed", func(b *removalTestBackend) { b.errorOpen = errors.Join(ErrNotInstalled, syscall.Errno(5)) }, syscall.Errno(5), 0},
		{"query", "service_removal_snapshot", "failed", func(b *removalTestBackend) { b.service.queryErr = fault }, fault, 1},
		{"query absent", "service_removal_snapshot", "failed", func(b *removalTestBackend) { b.service.queryErr = ErrNotInstalled }, ErrNotInstalled, 1},
		{"query marked for deletion", "service_removal_snapshot", "failed", func(b *removalTestBackend) { b.service.queryErr = syscall.Errno(1072) }, syscall.Errno(1072), 1},
		{"missing snapshot", "service_removal_binding", "mismatch", func(b *removalTestBackend) { b.s.snapshot.Exists = false }, ErrMismatch, 1},
		{"missing observer", "service_removal_reader", "missing", func(b *removalTestBackend) { b.serviceWithoutObserver = true }, ErrMismatch, 1},
		{"close", "service_removal_close", "failed", func(b *removalTestBackend) { b.service.closeErr = fault }, fault, 1},
		{"close absent", "service_removal_close", "failed", func(b *removalTestBackend) { b.service.closeErr = ErrNotInstalled }, ErrNotInstalled, 1},
		{"executable trust", "service_removal_executable", "failed", func(b *removalTestBackend) { b.verifyErr = ErrUnsafePath }, ErrUnsafePath, 1},
		{"executable hash", "service_removal_hash", "changed", func(b *removalTestBackend) { b.hash = strings.Repeat("b", 64) }, ErrMismatch, 1},
		{"executable pending code", "service_removal_executable", "failed", func(b *removalTestBackend) { b.verifyErr = syscall.Errno(1072) }, syscall.Errno(1072), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, r := removalFixture(t)
			tc.change(b)
			got, err := inspectRemoval(context.Background(), b, r)
			if !errors.Is(err, tc.cause) || got.Exists || b.s.closes != tc.closes {
				t.Fatalf("invalid observation: %+v, %v; closes %d", got, err, b.s.closes)
			}
			if tc.cause != nil {
				requireSetupDiagnostic(t, err, tc.stage, tc.category)
			}
			wantWait := tc.stage == "service_removal_open" || tc.stage == "service_removal_snapshot"
			if CanWaitRemovalObservation(err) != wantWait {
				t.Fatalf("wrong operational wait eligibility for %s", tc.name)
			}
			requireRemovalReadOnly(t, b)
		})
	}
}

func TestInspectRemovalCancellationClosesHandlesAndNeverCompletes(t *testing.T) {
	for _, stage := range []string{"entry", "layout", "open", "absent open", "query", "verify", "close"} {
		t.Run(stage, func(t *testing.T) {
			b, r := removalFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantOpen, wantRead, wantClose := 0, 0, 0
			switch stage {
			case "entry":
				cancel()
			case "layout":
				b.layoutHook = cancel
			case "open":
				b.openHook = cancel
				wantOpen, wantClose = 1, 1
			case "absent open":
				b.openHook, b.absent = cancel, true
				wantOpen = 1
			case "query":
				b.service.queryHook = cancel
				wantOpen, wantRead, wantClose = 1, 1, 1
			case "verify":
				b.verifyHook = cancel
				wantOpen, wantRead, wantClose = 1, 1, 1
			case "close":
				b.service.closeHook = cancel
				wantOpen, wantRead, wantClose = 1, 1, 1
			}
			got, err := inspectRemoval(ctx, b, r)
			if !errors.Is(err, context.Canceled) || got.Exists || len(b.opened) != wantOpen || b.service.removalReads != wantRead || b.s.closes != wantClose {
				t.Fatalf("cancelled observation completed or retained handle: %+v, %v", got, err)
			}
			if CanWaitRemovalObservation(err) {
				t.Fatal("cancelled observation eligible to wait")
			}
			requireSetupDiagnostic(t, err, "service_removal_context", "interrupted")
			requireRemovalReadOnly(t, b)
		})
	}
}

func TestInspectRemovalPreservesQueryAndCloseErrors(t *testing.T) {
	b, r := removalFixture(t)
	queryErr, closeErr := errors.New("query failed"), errors.New("close failed")
	b.service.queryErr, b.service.closeErr = queryErr, closeErr
	got, err := inspectRemoval(context.Background(), b, r)
	if got.Exists || !errors.Is(err, queryErr) || !errors.Is(err, closeErr) || b.s.closes != 1 {
		t.Fatalf("lost observation or close failure: %+v, %v", got, err)
	}
	if CanWaitRemovalObservation(err) {
		t.Fatal("failed handle closure eligible to wait")
	}
	requireSetupDiagnostic(t, err, "service_removal_snapshot", "failed")
	requireRemovalReadOnly(t, b)
}

func TestInspectRemovalPreservesPendingWithCloseOrCancellationFailure(t *testing.T) {
	for _, cancelOnClose := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelOnClose), func(t *testing.T) {
			b, r := removalFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.service.queryErr = syscall.Errno(1072)
			other := error(syscall.Errno(6))
			if cancelOnClose {
				b.service.closeHook = cancel
				other = context.Canceled
			} else {
				b.service.closeErr = other
			}
			got, err := inspectRemoval(ctx, b, r)
			if got.Exists || !errors.Is(err, syscall.Errno(1072)) || !errors.Is(err, other) || b.s.closes != 1 {
				t.Fatalf("pending masked another failure: %+v, %v", got, err)
			}
			if _, joined := errors.Unwrap(err).(interface{ Unwrap() []error }); !joined {
				t.Fatal("pending with another failure must not be a single cause")
			}
			if CanWaitRemovalObservation(err) {
				t.Fatal("pending with close/cancellation failure eligible to wait")
			}
			requireRemovalReadOnly(t, b)
		})
	}
}

func TestInspectRemovalDeadlineDoesNotOpen(t *testing.T) {
	b, r := removalFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got, err := inspectRemoval(ctx, b, r)
	if got.Exists || !errors.Is(err, context.DeadlineExceeded) || b.layouts != 0 || len(b.opened) != 0 {
		t.Fatalf("expired observation reached backend: %+v, %v", got, err)
	}
	requireRemovalReadOnly(t, b)
}

type removalFalseMissingError struct{}

func (removalFalseMissingError) Error() string { panic("must not format") }
func (removalFalseMissingError) Is(error) bool { panic("must not match") }

func TestRemovalOpenAbsenceRejectsAmbiguousAndMalformedChains(t *testing.T) {
	for _, err := range []error{ErrNotInstalled, fmt.Errorf("open: %w", ErrNotInstalled), setupStageError("service_open_service", "missing", ErrNotInstalled)} {
		if !removalOpenAbsent(err) {
			t.Fatal("unambiguous open absence rejected")
		}
	}
	var deep error = ErrNotInstalled
	for range 65 {
		deep = setupStageError("service_removal_open", "failed", deep)
	}
	for _, err := range []error{nil, syscall.Errno(5), errors.Join(ErrNotInstalled), errors.Join(ErrNotInstalled, syscall.Errno(5)),
		fmt.Errorf("open: %w", errors.Join(ErrNotInstalled, syscall.Errno(1072))), removalFalseMissingError{},
		&hostileUnwrapper{}, &cyclicDiagnosticCause{}, deep,
	} {
		if removalOpenAbsent(err) {
			t.Fatal("ambiguous, matching-only, malformed or cyclic error proved absence")
		}
	}
}

func TestRemovalObservationWaitEligibilityCannotBeForgedByCauses(t *testing.T) {
	b, r := removalFixture(t)
	b.errorOpen = syscall.Errno(1072)
	_, pending := inspectRemoval(context.Background(), b, r)
	if !CanWaitRemovalObservation(pending) {
		t.Fatal("clean SCM open failure lost eligibility")
	}
	for _, err := range []error{nil, syscall.Errno(1072), errors.Join(pending), fmt.Errorf("wrapper: %w", pending),
		removalFalseMissingError{}, &hostileUnwrapper{}, &cyclicDiagnosticCause{}, (*removalObservationError)(nil),
	} {
		if CanWaitRemovalObservation(err) {
			t.Fatal("unrecognized error gained operational eligibility")
		}
	}
	if pending.Error() != syscall.Errno(1072).Error() || fmt.Sprintf("%#v", pending) != pending.Error() || fmt.Sprintf("%+v", pending) != pending.Error() {
		t.Fatal("observation wrapper changed error rendering or exposed private fields")
	}
	requireSetupDiagnostic(t, pending, "service_removal_open", "failed")
	requireRemovalReadOnly(t, b)
}

func TestNativeRemovalSnapshotKeepsOrdinarySIDLookup(t *testing.T) {
	// Portable source guard complements fake lifecycle tests: it ensures the
	// native shared reader remains SID-free while Inspect retains real lookup.
	file, err := parser.ParseFile(token.NewFileSet(), "native_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || (fn.Name.Name != "Inspect" && fn.Name.Name != "inspectRemoval") {
			continue
		}
		methods[fn.Name.Name] = fn
	}
	for _, name := range []string{"Inspect", "inspectRemoval"} {
		fn := methods[name]
		if fn == nil {
			t.Fatalf("missing native %s", name)
		}
		calls := map[string]int{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch target := call.Fun.(type) {
			case *ast.Ident:
				calls[target.Name]++
			case *ast.SelectorExpr:
				calls[target.Sel.Name]++
			}
			return true
		})
		if name == "Inspect" {
			if calls["LookupServiceSID"] != 1 || calls["inspectRemoval"] != 1 {
				t.Fatalf("ordinary native inspection lost mandatory SID lookup: %v", calls)
			}
		} else if calls["LookupServiceSID"] != 0 || calls["LookupSID"] != 0 || calls["Inspect"] != 0 || calls["Config"] != 1 || calls["QueryServiceStatusEx"] != 1 || calls["queryConfig2"] != 3 {
			t.Fatalf("native removal reader lost complete SID-free configuration/status queries: %v", calls)
		}
	}
}
