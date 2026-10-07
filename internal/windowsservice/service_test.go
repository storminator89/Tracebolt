package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const fixtureSID = "S-1-5-80-1-2-3-4-5"

var fixtureHash = strings.Repeat("a", 64)

type fakeService struct {
	snapshot                                         Snapshot
	starts, stops, deletes, closes                   int
	inspectError, errorStart, errorStop, errorDelete error
}

func (s *fakeService) Inspect() (Snapshot, error) { return s.snapshot, s.inspectError }
func (s *fakeService) Start() error {
	s.starts++
	if s.errorStart == nil {
		s.snapshot.State = StartPending
	}
	return s.errorStart
}
func (s *fakeService) Stop() error {
	s.stops++
	if s.errorStop == nil {
		s.snapshot.State = StopPending
	}
	return s.errorStop
}
func (s *fakeService) Delete() error { s.deletes++; return s.errorDelete }
func (s *fakeService) Close() error  { s.closes++; return nil }

type fakeBackend struct {
	layout               Layout
	hash                 string
	s                    *fakeService
	created, verified    int
	createErr, errorOpen error
	lookupErr            error
	opened               []access
}

func (b *fakeBackend) Layout() (Layout, error)                 { return b.layout, nil }
func (b *fakeBackend) VerifyExecutable(Layout) (string, error) { b.verified++; return b.hash, nil }
func (b *fakeBackend) Open(a access) (service, error) {
	b.opened = append(b.opened, a)
	if b.errorOpen != nil {
		return nil, b.errorOpen
	}
	if b.s == nil {
		return nil, ErrNotInstalled
	}
	return b.s, nil
}
func (b *fakeBackend) Create(c Configuration) (service, error) {
	b.created++
	b.s = &fakeService{snapshot: Snapshot{Exists: true, Configuration: c, State: Stopped, ServiceSID: fixtureSID}}
	return b.s, b.createErr
}
func (b *fakeBackend) LookupSID() (string, error) { return fixtureSID, b.lookupErr }
func fixtureBackend(t *testing.T) *fakeBackend {
	t.Helper()
	l, err := layoutFromRoots(`D:\Program Files`, `D:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBackend{layout: l, hash: fixtureHash}
}
func installedFixture(t *testing.T) (*fakeBackend, Receipt) {
	t.Helper()
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	r, err := install(context.Background(), b, p)
	if err != nil {
		t.Fatal(err)
	}
	return b, r
}

func TestPlanAndInspectAreReadOnly(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if b.created != 0 || p.Existing.Exists || p.Configuration.Name != Name || p.Configuration.Account != Account {
		t.Fatalf("unsafe plan: %+v", p)
	}
	if p.Configuration.BinaryPath != `"D:\Program Files\Tracebolt\tracebolt-windows-service.exe" "--run-service"` {
		t.Fatal(p.Configuration.BinaryPath)
	}
	if !reflect.DeepEqual(p.Configuration.RequiredPrivileges, []string{RequiredPrivilege}) || p.Configuration.ServiceType != 16 || p.Configuration.SIDType != 1 {
		t.Fatal(p.Configuration)
	}
	if got, err := inspect(context.Background(), b); err != nil || got.Exists {
		t.Fatal(got, err)
	}
	for _, access := range b.opened {
		if access != readAccess {
			t.Fatal("plan requested mutating handle")
		}
	}
}
func TestCreateOnlyReceiptAndAsynchronousLifecycle(t *testing.T) {
	b, r := installedFixture(t)
	if !r.Complete || r.ServiceSID != fixtureSID || b.created != 1 {
		t.Fatal(r)
	}
	started, err := apply(context.Background(), b, r, startAccess)
	if err != nil || !started.Requested || started.Snapshot.State != StartPending {
		t.Fatal(started, err)
	}
	if b.s.starts != 1 {
		t.Fatal("start not requested exactly once")
	}
	if _, err = apply(context.Background(), b, r, startAccess); err == nil || b.s.starts != 1 {
		t.Fatal("restarted pending transition")
	}
	b.s.snapshot.State = Running
	result, err := apply(context.Background(), b, r, startAccess)
	if err != nil || result.Requested || b.s.starts != 1 {
		t.Fatal(result, err)
	}
	stopped, err := apply(context.Background(), b, r, stopAccess)
	if err != nil || !stopped.Requested || stopped.Snapshot.State != StopPending {
		t.Fatal(stopped, err)
	}
	if _, err = apply(context.Background(), b, r, deleteAccess); !errors.Is(err, ErrNotStopped) || b.s.deletes != 0 {
		t.Fatal("deleted non-stopped service", err)
	}
	b.s.snapshot.State = Stopped
	deleted, err := apply(context.Background(), b, r, deleteAccess)
	if err != nil || !deleted.DeletePending || !deleted.StateRetained || b.s.deletes != 1 {
		t.Fatal(deleted, err)
	}
}
func TestInstallRejectsExistingEvenIfConfigurationMatches(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	b.s = &fakeService{snapshot: Snapshot{Exists: true, Configuration: p.Configuration, State: Stopped, ServiceSID: fixtureSID}}
	if _, err = install(context.Background(), b, p); !errors.Is(err, ErrExisting) || b.created != 0 {
		t.Fatal(err)
	}
}
func TestPlanTamperingCannotChooseTarget(t *testing.T) {
	changes := map[string]func(*InstallPlan){
		"service name":    func(p *InstallPlan) { p.Configuration.Name = "Spooler" },
		"account":         func(p *InstallPlan) { p.Configuration.Account = "LocalSystem" },
		"shell":           func(p *InstallPlan) { p.Configuration.BinaryPath = `powershell.exe -c whoami` },
		"arguments":       func(p *InstallPlan) { p.Configuration.BinaryPath += ` "--config=other"` },
		"layout":          func(p *InstallPlan) { p.Layout.Executable = `D:\attacker.exe` },
		"debug privilege": func(p *InstallPlan) { p.Configuration.RequiredPrivileges = []string{"SeDebugPrivilege"} },
		"SID mode":        func(p *InstallPlan) { p.Configuration.SIDType = 0 },
		"startup":         func(p *InstallPlan) { p.Configuration.StartType = 0 },
		"dependencies":    func(p *InstallPlan) { p.Configuration.Dependencies = []string{"other"} },
		"marker":          func(p *InstallPlan) { p.InstallationID = "no" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b := fixtureBackend(t)
			p, err := plan(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			change(&p)
			if _, err = install(context.Background(), b, p); !errors.Is(err, ErrMismatch) || b.created != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestArtifactChangedAfterPlanFailsClosed(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	b.hash = strings.Repeat("b", 64)
	if _, err = install(context.Background(), b, p); !errors.Is(err, ErrMismatch) || b.created != 0 {
		t.Fatal(err)
	}
}
func TestPartialCreateNeverDeletesOrAdopts(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	b.createErr = errors.New("injected privilege configuration failure")
	r, err := install(context.Background(), b, p)
	if err == nil || r.Complete || r.InstallationID != p.InstallationID || b.s.deletes != 0 {
		t.Fatal(r, err)
	}
	if _, err = install(context.Background(), b, p); !errors.Is(err, ErrExisting) || b.created != 1 {
		t.Fatal("adopted partial service", err)
	}
	if _, err = apply(context.Background(), b, r, startAccess); !errors.Is(err, ErrMismatch) || b.s.starts != 0 {
		t.Fatal("used incomplete receipt", err)
	}
}
func TestLookupFailureRetainsCreatedService(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	b.lookupErr = errors.New("lookup failed")
	r, err := install(context.Background(), b, p)
	if err == nil || r.Complete || b.s.deletes != 0 {
		t.Fatal(r, err)
	}
}
func TestConfigOrReceiptMismatchPreventsAllMutations(t *testing.T) {
	changes := map[string]func(*fakeBackend, *Receipt){
		"foreign marker":  func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.Description = "foreign" },
		"binary replaced": func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.BinaryPath = `C:\evil.exe` },
		"LocalSystem":     func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.Account = "LocalSystem" },
		"service SID":     func(b *fakeBackend, r *Receipt) { b.s.snapshot.ServiceSID = "S-1-5-18" },
		"failure action":  func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.FailureActions = true },
		"trigger":         func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.Triggers = true },
		"receipt":         func(b *fakeBackend, r *Receipt) { r.Complete = false },
		"receipt config":  func(b *fakeBackend, r *Receipt) { r.ConfigurationSHA256 = fixtureHash },
		"receipt ID":      func(b *fakeBackend, r *Receipt) { r.InstallationID = strings.Repeat("c", 32) },
	}
	for name, change := range changes {
		for _, op := range []access{startAccess, stopAccess, deleteAccess} {
			t.Run(name+string(rune('0'+op)), func(t *testing.T) {
				b, r := installedFixture(t)
				change(b, &r)
				if _, err := apply(context.Background(), b, r, op); !errors.Is(err, ErrMismatch) {
					t.Fatal(err)
				}
				if b.s.starts+b.s.stops+b.s.deletes != 0 {
					t.Fatal("mutation after mismatch")
				}
			})
		}
	}
}
func TestStopAndUninstallRetainStateDespiteMissingBinary(t *testing.T) {
	b, r := installedFixture(t)
	b.hash = ""
	b.s.snapshot.State = Running
	if _, err := apply(context.Background(), b, r, stopAccess); err != nil {
		t.Fatal(err)
	}
	b.s.snapshot.State = Stopped
	result, err := apply(context.Background(), b, r, deleteAccess)
	if err != nil || !result.StateRetained {
		t.Fatal(result, err)
	}
}
func TestCancelledRequestNeverMutates(t *testing.T) {
	b, r := installedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := apply(ctx, b, r, startAccess); !errors.Is(err, context.Canceled) || b.s.starts != 0 {
		t.Fatal(err)
	}
}
func TestSIDValidation(t *testing.T) {
	for _, v := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-80-1-2-3-4", "S-1-5-80-1-2-3-4-5-6", "S-1-5-80-1-2-3-4-4294967296", "S-1-5-80-1-2-3-04-5"} {
		if validServiceSID(v) {
			t.Fatal(v)
		}
	}
	if !validServiceSID(fixtureSID) {
		t.Fatal("fixture SID rejected")
	}
}
func TestLayoutRejectsNonlocalAndAmbiguousRoots(t *testing.T) {
	for _, v := range []string{`\\server\share`, `C:relative`, `C:\safe\..\unsafe`, `C:\safe.`, `C:\safe `, "C:\\evil\" quoted", `C:\a:b`, `C:/Program Files`, `%ProgramFiles%`} {
		if _, err := layoutFromRoots(v, `C:\ProgramData`); err == nil {
			t.Fatal(v)
		}
	}
}

func TestInspectOwnedIsReadOnlyAndChecksExecutable(t *testing.T) {
	b, r := installedFixture(t)
	b.opened = nil
	got, err := inspectOwned(context.Background(), b, r)
	if err != nil || !got.Exists || got.State != Stopped {
		t.Fatal(got, err)
	}
	if !reflect.DeepEqual(b.opened, []access{readAccess}) || b.s.starts+b.s.stops+b.s.deletes != 0 || b.created != 1 {
		t.Fatal("owned inspection mutated or requested mutating access")
	}
	b.hash = strings.Repeat("f", 64)
	if _, err = inspectOwned(context.Background(), b, r); !errors.Is(err, ErrMismatch) {
		t.Fatal("changed executable accepted", err)
	}
	if b.s.starts+b.s.stops+b.s.deletes != 0 {
		t.Fatal("inspection requested control")
	}
}
func TestInspectOwnedRejectsForeignAndIncompleteRecords(t *testing.T) {
	for name, change := range map[string]func(*fakeBackend, *Receipt){
		"incomplete":        func(b *fakeBackend, r *Receipt) { r.Complete = false },
		"foreign marker":    func(b *fakeBackend, r *Receipt) { b.s.snapshot.Configuration.Description = "foreign" },
		"different SID":     func(b *fakeBackend, r *Receipt) { b.s.snapshot.ServiceSID = "S-1-5-80-9-8-7-6-5" },
		"different receipt": func(b *fakeBackend, r *Receipt) { r.ConfigurationSHA256 = fixtureHash },
	} {
		t.Run(name, func(t *testing.T) {
			b, r := installedFixture(t)
			change(b, &r)
			if _, err := inspectOwned(context.Background(), b, r); !errors.Is(err, ErrMismatch) {
				t.Fatal(err)
			}
			if b.s.starts+b.s.stops+b.s.deletes != 0 {
				t.Fatal("mutation in inspection")
			}
		})
	}
}
