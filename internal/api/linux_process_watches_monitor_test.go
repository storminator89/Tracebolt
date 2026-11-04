package api

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/linuxprocesswatch"
	"strings"
	"testing"
	"time"
)

type monitorProcessSource struct {
	now          time.Time
	input        linuxprocesswatch.Input
	err          error
	reads        int
	onRead       func()
	deviceErrors map[string]error
}

func (f *monitorProcessSource) Now() time.Time { return f.now }
func (f *monitorProcessSource) WithLinuxProcessWatch(ctx context.Context, device string, names []string, epoch string, fn func(linuxprocesswatch.Input, func(time.Time) error) error) error {
	f.reads++
	if f.onRead != nil {
		f.onRead()
	}
	if f.err != nil {
		return f.err
	}
	if e := f.deviceErrors[device]; e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	in := f.input
	in.DeviceID = device
	in.Epoch = epoch
	in.SourceToken = "processsource_" + epoch
	in.Counts = make([]linuxprocesswatch.Count, len(names))
	for i, n := range names {
		in.Counts[i] = linuxprocesswatch.Count{Name: n}
	}
	return fn(in, func(time.Time) error { return ctx.Err() })
}
func (f *monitorProcessSource) advance(seq int) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC).Add(time.Duration(seq) * 10 * time.Second)
	f.now = at.Add(time.Second)
	f.input.Sample = &linuxprocesswatch.Generation{Sequence: fmt.Sprint(seq), GenerationID: fmt.Sprintf("sample_%032x", seq), ManifestHash: strings.Repeat("e", 64), CaptureStartedAt: at, CaptureFinishedAt: at, ReceivedAt: at, TotalRows: 1}
}
func setupProcessMonitor(t *testing.T, enable bool) (*Server, *linuxProcessWatchMonitor, *monitorProcessSource) {
	t.Helper()
	app := setup(t)
	f := &monitorProcessSource{input: linuxprocesswatch.Input{DeviceID: "agent_" + strings.Repeat("a", 32), Identity: strings.Repeat("b", 64), Authorized: true, Available: true, Reason: "none", AuthorityUntil: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}}
	f.advance(1)
	m, e := newLinuxProcessWatchMonitor(app.store, f)
	if e != nil {
		t.Fatal(e)
	}
	app.linuxProcessWatches = m
	if enable {
		e = f.WithLinuxProcessWatch(context.Background(), f.input.DeviceID, []string{"daemon"}, m.epoch, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
			r := linuxprocesswatch.ConfigureRequest{RequestID: fmt.Sprintf("processrequest_%032x", 1), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
			_, _, e := app.store.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, f.Now, guard)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	f.reads = 0
	return app, m, f
}
func processMonitorState(t *testing.T, app *Server, f *monitorProcessSource) *linuxprocesswatch.State {
	t.Helper()
	s, e := app.store.LinuxProcessWatchState(context.Background(), f.input.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func evalProcessMonitor(t *testing.T, m *linuxProcessWatchMonitor) {
	t.Helper()
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestLinuxProcessWatchMonitorDefaultOffNoReads(t *testing.T) {
	app, m, f := setupProcessMonitor(t, false)
	evalProcessMonitor(t, m)
	evalProcessMonitor(t, m)
	s := processMonitorState(t, app, f)
	if f.reads != 0 || s.Policy.Enabled || s.Revision != 0 {
		t.Fatal("default-off monitor read or adopted source", f.reads, s)
	}
}
func TestLinuxProcessWatchMonitorIndependentOfBrowser(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	evalProcessMonitor(t, m)
	if s := processMonitorState(t, app, f); s.Progress[0].FailureCount != 0 {
		t.Fatal("enabling generation counted")
	}
	for seq := 2; seq <= 3; seq++ {
		f.advance(seq)
		evalProcessMonitor(t, m)
	}
	s := processMonitorState(t, app, f)
	if len(s.Incidents) != 1 || s.Incidents[0].State != "open" || s.Incidents[0].Opening.Samples != 2 {
		t.Fatal("background monitor failed", s)
	}
	evalProcessMonitor(t, m)
	if len(processMonitorState(t, app, f).Incidents) != 1 {
		t.Fatal("same snapshot opened another incident")
	}
}
func TestLinuxProcessWatchMonitorFailureBreaksContinuity(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	f.advance(2)
	evalProcessMonitor(t, m)
	if processMonitorState(t, app, f).Progress[0].FailureCount != 1 {
		t.Fatal("missing first failure")
	}
	oldEpoch := m.epoch
	f.err = errors.New("source read unavailable")
	if e := m.evaluate(context.Background()); !errors.Is(e, f.err) || m.deviceEpochs[f.input.DeviceID] != "" {
		t.Fatal("failed pass retained epoch", e)
	}
	f.err = nil
	f.advance(3)
	evalProcessMonitor(t, m)
	s := processMonitorState(t, app, f)
	if s.Epoch == oldEpoch || s.Epoch != m.deviceEpochs[f.input.DeviceID] || s.Progress[0].FailureCount != 0 || len(s.Incidents) != 0 || s.SeenSequence != 3 {
		t.Fatal("recovery bridged outage", s)
	}
	f.advance(4)
	evalProcessMonitor(t, m)
	if len(processMonitorState(t, app, f).Incidents) != 0 {
		t.Fatal("incident opened before two post-recovery generations")
	}
	f.advance(5)
	evalProcessMonitor(t, m)
	if len(processMonitorState(t, app, f).Incidents) != 1 {
		t.Fatal("fresh generations did not resume monitoring")
	}
}
func TestLinuxProcessWatchMonitorRestartConsumesExistingGeneration(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	f.advance(2)
	evalProcessMonitor(t, m)
	next, e := newLinuxProcessWatchMonitor(app.store, f)
	if e != nil {
		t.Fatal(e)
	}
	if next.epoch == m.epoch {
		t.Fatal("restart reused epoch")
	}
	evalProcessMonitor(t, next)
	s := processMonitorState(t, app, f)
	if s.Progress[0].FailureCount != 0 || s.SeenSequence != 2 || len(s.Incidents) != 0 {
		t.Fatal("restart credited existing generation", s)
	}
	f.advance(3)
	evalProcessMonitor(t, next)
	if len(processMonitorState(t, app, f).Incidents) != 0 {
		t.Fatal("restart bridged old streak")
	}
	f.advance(4)
	evalProcessMonitor(t, next)
	if len(processMonitorState(t, app, f).Incidents) != 1 {
		t.Fatal("new continuity did not resume")
	}
}
func TestLinuxProcessWatchSchedulerRunsDespiteHealthFailure(t *testing.T) {
	for _, failProcess := range []bool{false, true} {
		t.Run(fmt.Sprint(failProcess), func(t *testing.T) {
			app, _, f := setupProcessMonitor(t, true)
			f.advance(2)
			healthErr := errors.New("linux health source failed")
			h := &observedHealthSource{at: f.now, err: healthErr}
			app.health = &healthMonitor{store: app.store, source: h}
			var processErr error
			if failProcess {
				processErr = errors.New("process source failed")
				f.err = processErr
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observed := 0
			warnings := 0
			e := app.RunHealthMonitorObserved(ctx, func() { warnings++ }, func(_ time.Time, e error) {
				observed++
				if f.reads != 1 || !errors.Is(e, healthErr) || processErr != nil && !errors.Is(e, processErr) {
					t.Error("scheduler skipped process source or lost errors", e, f.reads)
				}
				cancel()
			})
			if e != nil || observed != 1 || warnings != 1 {
				t.Fatal("scheduler did not stop cleanly", e, observed, warnings)
			}
			if !failProcess && processMonitorState(t, app, f).Progress[0].FailureCount != 1 {
				t.Fatal("health failure blocked process evaluation")
			}
		})
	}
}
func TestLinuxProcessWatchSchedulerCancellationStopsBeforeProcessRead(t *testing.T) {
	app, _, f := setupProcessMonitor(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &observedHealthSource{at: f.now, onRead: cancel}
	app.health = &healthMonitor{store: app.store, source: h}
	if e := app.RunHealthMonitorObserved(ctx, nil, func(time.Time, error) { t.Error("canceled evaluation observed") }); e != nil {
		t.Fatal(e)
	}
	if f.reads != 0 {
		t.Fatal("scheduler read process source after shutdown")
	}
}

func TestLinuxProcessWatchMonitorDisabledLedgerNoSourceReads(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	e := f.WithLinuxProcessWatch(context.Background(), f.input.DeviceID, nil, m.epoch, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
		r := linuxprocesswatch.ConfigureRequest{ExpectedRevision: 1, RequestID: fmt.Sprintf("processrequest_%032x", 2), SourceToken: in.SourceToken}
		_, _, e := app.store.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, f.Now, guard)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	before := processMonitorState(t, app, f)
	f.reads = 0
	f.err = errors.New("disabled source must not be read")
	f.advance(2)
	evalProcessMonitor(t, m)
	s := processMonitorState(t, app, f)
	if f.reads != 0 || s.Policy.Enabled || s.Revision != before.Revision || s.ClockFloor.Before(before.ClockFloor) || len(s.Progress) != 0 {
		t.Fatal("disabled monitor read source or changed policy", f.reads, s)
	}
}

func TestLinuxProcessWatchMonitorOneFailedDeviceDoesNotStarveAnother(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	failed := "agent_" + strings.Repeat("c", 32)
	e := f.WithLinuxProcessWatch(context.Background(), failed, []string{"daemon"}, m.epoch, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
		r := linuxprocesswatch.ConfigureRequest{RequestID: fmt.Sprintf("processrequest_%032x", 1), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
		_, _, e := app.store.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, f.Now, guard)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	f.deviceErrors = map[string]error{failed: errors.New("revoked or unavailable source")}
	for seq := 2; seq <= 3; seq++ {
		f.advance(seq)
		if e = m.evaluate(context.Background()); e == nil {
			t.Fatal("failed device omitted")
		}
	}
	if s := processMonitorState(t, app, f); len(s.Incidents) != 1 || s.Incidents[0].State != "open" {
		t.Fatal("unrelated failure starved healthy device", s)
	}
	f.deviceErrors = nil
	f.advance(4)
	evalProcessMonitor(t, m)
	s, e := app.store.LinuxProcessWatchState(context.Background(), failed)
	if e != nil || len(s.Incidents) != 0 || s.Progress[0].FailureCount != 0 {
		t.Fatal("failed device bridged unavailable period", s, e)
	}
	for seq := 5; seq <= 6; seq++ {
		f.advance(seq)
		evalProcessMonitor(t, m)
	}
	s, e = app.store.LinuxProcessWatchState(context.Background(), failed)
	if e != nil || len(s.Incidents) != 1 {
		t.Fatal("failed device did not resume independently", s, e)
	}
}

func TestLinuxProcessWatchMonitorRetentionIndependentOfUnavailableSource(t *testing.T) {
	app, m, f := setupProcessMonitor(t, true)
	for seq := 2; seq <= 3; seq++ {
		f.advance(seq)
		evalProcessMonitor(t, m)
	}
	s := processMonitorState(t, app, f)
	stoppedAt := f.now
	// An explicit same-scope policy replacement ends the first incident, then
	// two later source generations open a separate still-unresolved incident.
	e := f.WithLinuxProcessWatch(context.Background(), f.input.DeviceID, []string{"daemon"}, m.epoch, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
		r := linuxprocesswatch.ConfigureRequest{ExpectedRevision: s.Revision, RequestID: fmt.Sprintf("processrequest_%032x", 2), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
		_, _, e := app.store.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, f.Now, guard)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	for seq := 4; seq <= 5; seq++ {
		f.advance(seq)
		evalProcessMonitor(t, m)
	}
	before := processMonitorState(t, app, f)
	if len(before.Incidents) != 2 || before.Incidents[0].State != "monitoring_stopped" || before.Incidents[1].State != "open" {
		t.Fatal("fixture", before)
	}
	f.now = stoppedAt.Add(linuxprocesswatch.Retention + time.Second)
	f.err = errors.New("revoked/expired source cannot grant a lease")
	if e = m.evaluate(context.Background()); !errors.Is(e, f.err) {
		t.Fatal(e)
	}
	after := processMonitorState(t, app, f)
	if len(after.Incidents) != 1 || after.Incidents[0].ID != before.Incidents[1].ID || after.Incidents[0].State != "open" || after.EarlierOmitted != 1 || after.Revision != before.Revision || after.Policy.Enabled != before.Policy.Enabled {
		t.Fatal("source outage retained terminal history or changed live policy", after)
	}
	if !after.ClockFloor.Equal(f.now) {
		t.Fatal("retention clock not persisted")
	}
}
