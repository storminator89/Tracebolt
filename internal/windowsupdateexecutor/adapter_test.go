package windowsupdateexecutor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	job "localrmm/internal/windowsupdatejob"
)

type fakeCOM struct {
	cleanupStarted, cleanupRelease chan struct{}
	before                         func(string)
	mu                             sync.Mutex
	values                         map[string]value
	objects                        map[string]*fakeObject
	calls                          []string
	queries                        []string
	installs                       int
	closed                         bool
	thread                         uint64
	wrongThread                    bool
	fail, ignorePut                string
	noInstaller2                   bool
	tokenErr                       error
	installStarted                 chan struct{}
	installRelease                 chan struct{}
}
type fakeObject struct {
	f    *fakeCOM
	name string
}

func (f *fakeCOM) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := testThreadID()
	if f.thread == 0 {
		f.thread = id
	} else if f.thread != id {
		f.wrongThread = true
	}
	f.calls = append(f.calls, call)
}
func (o *fakeObject) invoke(ctx context.Context, name string, flags uint16, args ...value) (value, error) {
	key := o.name + "." + name
	if o.f.before != nil {
		o.f.before(key)
	}
	o.f.note(fmt.Sprintf("%s:%d", key, flags))
	if o.f.fail == key {
		return value{}, ErrUnavailable
	}
	if flags == put {
		if o.f.ignorePut != key {
			o.f.values[key] = args[0]
		}
		return value{}, nil
	}
	if key == "searcher.Search" {
		o.f.queries = append(o.f.queries, args[0].text)
	}
	if key == "collection.Add" {
		if len(args) != 1 || args[0].object != o.f.objects["update"] {
			return value{}, ErrIdentity
		}
		o.f.values["collection.Count"] = integer(1)
		o.f.values["collection.Item"] = args[0]
		return integer(0), nil
	}
	if key == "installer.Install" {
		o.f.mu.Lock()
		o.f.installs++
		o.f.mu.Unlock()
		if o.f.installStarted != nil {
			close(o.f.installStarted)
			<-o.f.installRelease
		}
	}
	if (name == "Item" || name == "GetUpdateResult") && (len(args) != 1 || args[0].kind != intKind || args[0].number != 0) {
		return value{}, ErrIdentity
	}
	v, ok := o.f.values[key]
	if !ok {
		return value{}, ErrUnavailable
	}
	return v, nil
}
func (o *fakeObject) same(other comObject) (bool, error) {
	o.f.note(o.name + ".same")
	b, ok := other.(*fakeObject)
	return ok && b == o, nil
}
func (o *fakeObject) close() { o.f.note(o.name + ".close") }
func (f *fakeCOM) session(context.Context) (comObject, error) {
	f.note("runtime.session")
	return f.objects["session"], nil
}
func (f *fakeCOM) collection(context.Context) (comObject, error) {
	f.note("runtime.collection")
	return f.objects["collection"], nil
}
func (f *fakeCOM) installer2(_ context.Context, o comObject) (comObject, error) {
	f.note("runtime.installer2")
	if f.noInstaller2 {
		return nil, ErrUnavailable
	}
	return o, nil
}
func (f *fakeCOM) verifyToken() error { f.note("runtime.token"); return f.tokenErr }
func (f *fakeCOM) close() {
	f.note("runtime.close")
	if f.cleanupStarted != nil {
		close(f.cleanupStarted)
		<-f.cleanupRelease
	}
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

var selection = job.Selection{UpdateID: "12345678-1234-5678-9abc-1234567890ab", Revision: 7}

func fixture() (*Adapter, *fakeCOM) {
	f := &fakeCOM{values: map[string]value{}, objects: map[string]*fakeObject{}}
	for _, name := range []string{"session", "searcher", "search", "updates", "update", "identity", "installer", "collection", "bundles", "behavior", "result", "perUpdate"} {
		f.objects[name] = &fakeObject{f: f, name: name}
	}
	link := func(key, name string) { f.values[key] = objectArg(f.objects[name]) }
	link("session.CreateUpdateSearcher", "searcher")
	link("session.CreateUpdateInstaller", "installer")
	link("searcher.Search", "search")
	link("search.Updates", "updates")
	link("updates.Item", "update")
	link("update.Identity", "identity")
	link("update.BundledUpdates", "bundles")
	link("update.InstallationBehavior", "behavior")
	link("installer.Install", "result")
	link("result.GetUpdateResult", "perUpdate")
	f.values["search.ResultCode"] = integer(2)
	f.values["updates.Count"] = integer(1)
	f.values["collection.Count"] = integer(0)
	f.values["identity.UpdateID"] = value{kind: textKind, text: strings.ToUpper(selection.UpdateID)}
	f.values["identity.RevisionNumber"] = integer(int32(selection.Revision))
	f.values["update.Type"] = integer(1)
	f.values["bundles.Count"] = integer(0)
	f.values["behavior.RebootBehavior"] = integer(2)
	for _, key := range []string{"update.IsInstalled", "update.IsHidden", "update.CanRequireSource", "behavior.CanRequestUserInput", "behavior.RequiresNetworkConnectivity", "installer.IsBusy", "installer.RebootRequiredBeforeInstallation"} {
		f.values[key] = boolean(false)
	}
	f.values["update.IsDownloaded"] = boolean(true)
	f.values["update.EulaAccepted"] = boolean(true)
	f.values["perUpdate.ResultCode"] = integer(2)
	f.values["perUpdate.HResult"] = integer(0)
	f.values["perUpdate.RebootRequired"] = boolean(true)
	a := newAdapter(func(ctx context.Context) (comRuntime, error) {
		f.note("runtime.open")
		if err := f.verifyToken(); err != nil {
			return nil, err
		}
		return f, nil
	}, func() time.Time { return time.Unix(1700000000, 0) })
	a.checkStart = func(context.Context, time.Time) error { return nil } // Inert kernel fence fixture.
	return a, f
}
func prepare(t *testing.T, a *Adapter) *prepared {
	t.Helper()
	p, err := a.PrepareExact(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*prepared)
}
func inspect(t *testing.T, p *prepared) job.Readiness {
	t.Helper()
	r, err := p.Inspect(context.Background())
	if err != nil || r.Reason() != "ready" {
		t.Fatalf("%+v %v", r, err)
	}
	return r
}
func TestExactCachedInstallUsesOneOwnerAndPerUpdateResult(t *testing.T) {
	a, f := fixture()
	p := prepare(t, a)
	inspect(t, p)
	result, err := p.InstallOnce(context.Background())
	if err != nil || result.OperationResult != 2 || result.HResult != 0 || result.RebootRequired != job.Yes {
		t.Fatal(result, err)
	}
	if _, err = p.InstallOnce(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal("second attempt", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.queries) != 1 || f.queries[0] != "Type='Software' and IsInstalled=0 and IsHidden=0 and UpdateID='12345678-1234-5678-9abc-1234567890ab' and RevisionNumber=7" {
		t.Fatal(f.queries)
	}
	if f.installs != 1 || !f.closed || f.wrongThread {
		t.Fatal("ownership", f.installs, f.closed, f.wrongThread)
	}
	joined := strings.Join(f.calls, "\n")
	for _, forbidden := range []string{"Download:", "AcceptEula:", "RunWizard:", "Reboot:", "bundles.Item:", "result.ResultCode:"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal(joined)
		}
	}
	for _, required := range []string{"searcher.Online:4", "searcher.CanAutomaticallyUpgradeService:4", "installer.AllowSourcePrompts:4", "installer.IsForced:4", "installer.ForceQuiet:4", "runtime.installer2", "perUpdate.HResult:2", "perUpdate.RebootRequired:2"} {
		if !strings.Contains(joined, required) {
			t.Fatal(required)
		}
	}
}
func TestPreparationFailClosed(t *testing.T) {
	cases := map[string]func(*fakeCOM){
		"no_match": func(f *fakeCOM) { f.values["updates.Count"] = integer(0) }, "multiple": func(f *fakeCOM) { f.values["updates.Count"] = integer(2) }, "partial_search": func(f *fakeCOM) { f.values["search.ResultCode"] = integer(3) }, "revision": func(f *fakeCOM) { f.values["identity.RevisionNumber"] = integer(8) }, "identity": func(f *fakeCOM) {
			f.values["identity.UpdateID"] = value{kind: textKind, text: "00000000-0000-0000-0000-000000000000"}
		}, "installer2": func(f *fakeCOM) { f.noInstaller2 = true }, "online": func(f *fakeCOM) { f.ignorePut = "searcher.Online"; f.values[f.ignorePut] = boolean(true) }, "self_upgrade": func(f *fakeCOM) {
			f.ignorePut = "searcher.CanAutomaticallyUpgradeService"
			f.values[f.ignorePut] = boolean(true)
		}, "quiet_readback": func(f *fakeCOM) { f.ignorePut = "installer.ForceQuiet"; f.values[f.ignorePut] = boolean(false) }, "source_readback": func(f *fakeCOM) { f.ignorePut = "installer.AllowSourcePrompts"; f.values[f.ignorePut] = boolean(true) }, "forced_readback": func(f *fakeCOM) { f.ignorePut = "installer.IsForced"; f.values[f.ignorePut] = boolean(true) }, "privilege": func(f *fakeCOM) { f.tokenErr = ErrAdministrator },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, f := fixture()
			mutate(f)
			p, err := a.PrepareExact(context.Background(), selection)
			if err == nil || p != nil {
				t.Fatal("accepted", err)
			}
			if f.installs != 0 {
				t.Fatal("installed")
			}
		})
	}
	a, f := fixture()
	bad := selection
	bad.UpdateID += "' or IsInstalled=1"
	if _, err := a.PrepareExact(context.Background(), bad); err == nil || len(f.calls) != 0 {
		t.Fatal("unvalidated input touched native")
	}
}
func TestAllUnknownReadinessFailsWithoutSkippingOtherReads(t *testing.T) {
	fields := []string{"update.Type", "update.IsInstalled", "update.IsHidden", "update.IsDownloaded", "update.EulaAccepted", "update.CanRequireSource", "bundles.Count", "behavior.CanRequestUserInput", "behavior.RequiresNetworkConnectivity", "behavior.RebootBehavior", "installer.RebootRequiredBeforeInstallation", "installer.IsBusy", "searcher.Online"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			a, f := fixture()
			p := prepare(t, a)
			f.fail = field
			r, err := p.Inspect(context.Background())
			if err != nil || r.Reason() == "ready" {
				t.Fatal(r, err)
			}
			if _, err = p.InstallOnce(context.Background()); err == nil {
				t.Fatal("unknown installed")
			}
			_ = p.Close()
			if f.installs != 0 {
				t.Fatal("native mutation")
			}
			for _, other := range []string{"update.EulaAccepted:2", "behavior.RequiresNetworkConnectivity:2", "installer.IsBusy:2"} {
				if !strings.Contains(strings.Join(f.calls, "\n"), other) {
					t.Fatal("read skipped", other)
				}
			}
		})
	}
}
func TestChangedReadinessAndSafeguardsBlockFinalCall(t *testing.T) {
	changes := map[string]value{"update.Type": integer(2), "update.IsInstalled": boolean(true), "update.IsHidden": boolean(true), "update.IsDownloaded": boolean(false), "update.EulaAccepted": boolean(false), "update.CanRequireSource": boolean(true), "bundles.Count": integer(2147483647), "behavior.CanRequestUserInput": boolean(true), "behavior.RequiresNetworkConnectivity": boolean(true), "behavior.RebootBehavior": integer(1), "installer.RebootRequiredBeforeInstallation": boolean(true), "installer.IsBusy": boolean(true), "installer.ForceQuiet": boolean(false), "installer.IsForced": boolean(true), "installer.AllowSourcePrompts": boolean(true), "collection.Count": integer(2), "identity.RevisionNumber": integer(8), "searcher.Online": boolean(true)}
	for name, changed := range changes {
		t.Run(name, func(t *testing.T) {
			a, f := fixture()
			p := prepare(t, a)
			inspect(t, p)
			f.values[name] = changed
			if _, err := p.InstallOnce(context.Background()); err == nil {
				t.Fatal("change accepted")
			}
			_ = p.Close()
			if f.installs != 0 {
				t.Fatal("installed after changed readiness")
			}
		})
	}
}
func TestPerUpdateFailureAndIncompleteResultsNeverBecomeSuccess(t *testing.T) {
	for _, code := range []int32{0, 1, 3, 4, 5, 6} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			a, f := fixture()
			f.values["perUpdate.ResultCode"] = integer(code)
			f.values["perUpdate.HResult"] = integer(-2147467259)
			p := prepare(t, a)
			inspect(t, p)
			r, err := p.InstallOnce(context.Background())
			if code > 5 && err == nil {
				t.Fatal("invalid result")
			}
			if code <= 5 && (err != nil || r.OperationResult != uint32(code) || r.HResult != -2147467259) {
				t.Fatal(r, err)
			}
			_ = p.Close()
		})
	}
	for _, field := range []string{"result.GetUpdateResult", "perUpdate.ResultCode", "perUpdate.HResult", "perUpdate.RebootRequired"} {
		t.Run(field, func(t *testing.T) {
			a, f := fixture()
			p := prepare(t, a)
			inspect(t, p)
			f.fail = field
			if _, err := p.InstallOnce(context.Background()); err == nil {
				t.Fatal("missing per-update proof")
			}
			_ = p.Close()
		})
	}
}
func TestTimeoutDoesNotReleaseRunningCOMOrPermitRetry(t *testing.T) {
	a, f := fixture()
	a.installLimit = 15 * time.Millisecond
	f.installStarted = make(chan struct{})
	f.installRelease = make(chan struct{})
	p := prepare(t, a)
	inspect(t, p)
	done := make(chan error, 1)
	go func() { _, err := p.InstallOnce(context.Background()); done <- err }()
	<-f.installStarted
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := p.Close(); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		t.Fatal("released COM during running install")
	}
	if _, err := a.PrepareExact(context.Background(), selection); err == nil {
		t.Fatal("retry during uncertain call")
	}
	close(f.installRelease)
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("owner did not release after call returned")
	}
	if _, err := a.PrepareExact(context.Background(), selection); err == nil {
		t.Fatal("late success cleared uncertainty")
	}
	if f.installs != 1 || !f.closed || f.wrongThread {
		t.Fatal("ownership or retry violated")
	}
}
func TestDurationIsSeparateAndNoInspectCannotInstall(t *testing.T) {
	if installationLimit <= job.PreviewLifetime || preparationLimit > job.PreviewLifetime {
		t.Fatal("duration tied to preview")
	}
	a, f := fixture()
	p := prepare(t, a)
	if _, err := p.InstallOnce(context.Background()); err == nil {
		t.Fatal("installed without review")
	}
	_ = p.Close()
	if f.installs != 0 {
		t.Fatal("installed")
	}
}

func TestStartFenceExpiresDuringFinalReadiness(t *testing.T) {
	deadline := time.Unix(1700000001, 0)
	a, f := fixture()
	at := time.Unix(1700000000, 0)
	a.now = func() time.Time { return at }
	a.checkStart = func(_ context.Context, now time.Time) error {
		if now.Unix() < 1700000000 || !now.Before(deadline) {
			return job.ErrExpired
		}
		return nil
	}
	p := prepare(t, a)
	inspect(t, p)
	f.before = func(key string) {
		if key == "installer.IsBusy" {
			at = deadline
		}
	}
	if _, err := p.InstallOnce(context.Background()); !errors.Is(err, job.ErrExpired) {
		t.Fatal(err)
	}
	_ = p.Close()
	if f.installs != 0 {
		t.Fatal("expired start dispatched")
	}
}
func TestMissingStartFenceRejectsNativeDispatch(t *testing.T) {
	a, f := fixture()
	a.checkStart = job.CheckInstallStart
	p := prepare(t, a)
	inspect(t, p)
	if _, err := p.InstallOnce(context.Background()); !errors.Is(err, job.ErrAuthority) {
		t.Fatal(err)
	}
	_ = p.Close()
	if f.installs != 0 {
		t.Fatal("missing fence dispatched")
	}
}

func assertAdmissionHeld(t *testing.T, a *Adapter, p *prepared, poisoned bool) {
	t.Helper()
	a.mu.Lock()
	busy, uncertain := a.busy, a.uncertain
	a.mu.Unlock()
	if !busy || uncertain != poisoned {
		t.Fatalf("publication released admission: busy=%v uncertain=%v want poison=%v", busy, uncertain, poisoned)
	}
	select {
	case <-p.done:
		t.Fatal("owner exited before caller settled")
	default:
	}
	if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("concurrent preparation admitted", err)
	}
}
func TestInstallPublicationPoisonsBeforeUnscheduledCaller(t *testing.T) {
	for _, nativeError := range []bool{false, true} {
		t.Run(fmt.Sprint(nativeError), func(t *testing.T) {
			a, f := fixture()
			p := prepare(t, a)
			inspect(t, p)
			if nativeError {
				f.fail = "installer.Install"
			} else {
				f.values["perUpdate.ResultCode"] = integer(4)
			}
			// Deliberately bypass the ordinary caller's poison handling and withhold its
			// acknowledgement. Only owner-side ordering can satisfy this assertion.
			r := request{ctx: context.Background(), install: true, reply: make(chan reply, 1), settled: make(chan struct{})}
			p.requests <- r
			out := <-r.reply
			if nativeError && out.err == nil {
				t.Fatal("missing injected error")
			}
			assertAdmissionHeld(t, a, p, true)
			close(r.settled)
			<-p.done
			if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
				t.Fatal("native failure reopened admission", err)
			}
		})
	}
}
func TestSuccessfulReplyCannotReleaseAdmissionBeforeCallerDecidesTimeout(t *testing.T) {
	a, _ := fixture()
	p := prepare(t, a)
	inspect(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := request{ctx: ctx, install: true, reply: make(chan reply, 1), settled: make(chan struct{})}
	p.requests <- r
	if out := <-r.reply; out.err != nil || out.result.OperationResult != 2 {
		t.Fatal(out)
	}
	assertAdmissionHeld(t, a, p, false)
	// Cancellation arrives while the successful buffered reply's caller remains
	// unscheduled. The caller poisons before releasing its settlement handshake.
	cancel()
	p.abort()
	close(r.settled)
	<-p.done
	if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("late success revived canceled caller", err)
	}
}
func TestPreparationPublicationPoisonsBeforeUnscheduledCaller(t *testing.T) {
	for _, stage := range []string{"canceled", "open", "exact_search"} {
		t.Run(stage, func(t *testing.T) {
			a, f := fixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "canceled":
				cancel()
			case "open":
				f.tokenErr = ErrAdministrator
			case "exact_search":
				f.values["updates.Count"] = integer(2)
			}
			a.busy = true
			p := &prepared{owner: a, requests: make(chan request), stop: make(chan struct{}), done: make(chan struct{}), readySettled: make(chan struct{})}
			ready := make(chan error, 1)
			go p.run(ctx, selection, ready)
			if err := <-ready; err == nil {
				t.Fatal("missing preparation failure")
			}
			assertAdmissionHeld(t, a, p, true)
			close(p.readySettled)
			<-p.done
			if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
				t.Fatal("failed preparation reopened admission", err)
			}
		})
	}
}

func TestCloseTimeoutSettlementCannotPoisonCompletedOrReusedOwner(t *testing.T) {
	a, _ := fixture()
	p := prepare(t, a)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	// Model a Close timer already fired while its caller was descheduled. The
	// completion transition has since finished, so late settlement must choose
	// completed, even after the adapter's slot has been reused by another owner.
	fresh, _ := fixture()
	a.open = fresh.open
	next := prepare(t, a)
	if p.poisonIfUnfinished() {
		t.Fatal("late timeout relabeled completed owner")
	}
	// Model a stale active=true observation by a descheduled concurrent Close.
	p.mu.Lock()
	p.active = true
	p.mu.Unlock()
	if err := p.Close(); err != nil {
		t.Fatal("repeated completed/previously-active Close", err)
	}
	a.mu.Lock()
	poisoned := a.uncertain
	a.mu.Unlock()
	if poisoned {
		t.Fatal("stale Close poisoned new owner")
	}
	inspect(t, next)
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestCloseDuringBlockedCleanupPoisonsBeforeAdmissionRelease(t *testing.T) {
	a, f := fixture()
	f.cleanupStarted = make(chan struct{})
	f.cleanupRelease = make(chan struct{})
	p := prepare(t, a)
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	<-f.cleanupStarted
	// This is the exact timer settlement used by Close. Keep cleanup blocked so
	// completion cannot race past the decision or release the admission slot.
	if !p.poisonIfUnfinished() {
		t.Fatal("uncompleted cleanup reported complete")
	}
	a.mu.Lock()
	busy, poisoned := a.busy, a.uncertain
	a.mu.Unlock()
	if !busy || !poisoned {
		t.Fatal("cleanup uncertainty was not atomic")
	}
	if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("new preparation during cleanup", err)
	}
	close(f.cleanupRelease)
	<-p.done
	if err := <-closed; err != nil && !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("cleanup completion cleared recorded uncertainty", err)
	}
}
