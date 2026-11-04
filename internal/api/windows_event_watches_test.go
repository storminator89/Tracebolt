package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventwatch"
	"localrmm/internal/windowsmanaged"
	"strings"
	"testing"
	"time"
)

type fixtureEventWatchSource struct {
	now          time.Time
	input        windowseventwatch.Input
	lease        func(int)
	calls        int
	viewMismatch bool
	fail         bool
}

func (f *fixtureEventWatchSource) Now() time.Time { return f.now }
func (f *fixtureEventWatchSource) WindowsContactInputs(ctx context.Context, _ time.Time) ([]windowscontact.Input, error) {
	if f.fail {
		return nil, errors.New("source unavailable")
	}
	return []windowscontact.Input{f.input.Source}, ctx.Err()
}
func (f *fixtureEventWatchSource) WindowsInventoryView(ctx context.Context, id string, _ time.Time) (enrollmentstore.WindowsInventoryView, error) {
	s := f.input.Source.Sequence
	r := f.input.Source.ReceivedAt
	v := enrollmentstore.WindowsInventoryView{DeviceID: id, Status: "fresh", Sequence: &s, ReceivedAt: &r, Events: f.input.Events}
	if f.input.Events != nil {
		v.Snapshot = &windowsmanaged.Snapshot{GenerationID: f.input.Events.GenerationID, CollectedAt: f.input.Events.CollectedAt}
	}
	if f.viewMismatch {
		s++
	}
	return v, ctx.Err()
}
func (f *fixtureEventWatchSource) WithWindowsNotificationAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	return fn(func(at time.Time) error {
		f.calls++
		if f.lease != nil {
			f.lease(f.calls)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !f.input.Source.Authorized || f.input.Source.Sequence != in.Sequence || f.now.Before(at) || !f.now.Before(in.AuthorityUntil) {
			return enrollmentstate.ErrProof
		}
		return nil
	})
}
func installEventWatchFixture(t *testing.T, o operatorFixture) (*windowsEventWatchMonitor, *fixtureEventWatchSource) {
	t.Helper()
	at := time.Now().UTC().Round(0)
	in := windowseventwatch.Input{Source: contactFixtureInput(at), Events: &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("d", 32), GenerationID: "sample_" + strings.Repeat("e", 32), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "10", EventID: 42, Provider: "Fixture", Level: 2, Timestamp: at}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}}
	in.Source.AuthorityUntil = at.Add(30 * 24 * time.Hour)
	f := &fixtureEventWatchSource{now: at, input: in}
	m := &windowsEventWatchMonitor{store: o.app.store, source: f}
	o.app.windowsEventWatches = m
	return m, f
}
func eventWatchPolicyBody(f *fixtureEventWatchSource) map[string]any {
	return map[string]any{"requestId": "eventrequest_" + strings.Repeat("a", 32), "sourceToken": windowseventwatch.SourceToken(f.input), "expectedRevision": 0, "enabled": true, "selectors": []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, "retentionAcknowledged": true}
}
func advanceEventWatch(f *fixtureEventWatchSource, id string) {
	f.now = f.now.Add(time.Minute)
	f.input.Source.Sequence++
	f.input.Source.ReceivedAt = f.now
	f.input.Events.CollectedAt = f.now
	f.input.Events.GenerationID = "sample_" + strings.Repeat("f", 32)
	f.input.Events.Channels[0].Rows[0].RecordID = id
	f.input.Events.Channels[0].Rows[0].Timestamp = f.now
}
func TestWindowsEventWatchAPIConsentBaselineObservedMatchAndReview(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installEventWatchFixture(t, o)
	path := "/api/devices/" + f.input.Source.DeviceID + "/windows-event-watches"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal(r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["revision"] != float64(0) || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal(r.StatusCode, v)
	}
	records, e := o.app.store.WindowsEventWatchRecords(context.Background())
	if e != nil || len(records) != 0 {
		t.Fatal("GET wrote", e)
	}
	body := eventWatchPolicyBody(f)
	body["retentionAcknowledged"] = false
	if r, _ = o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("implicit consent", r.StatusCode)
	}
	body["retentionAcknowledged"] = true
	if r, _ = o.call(t, "POST", path+"/policy", body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF", r.StatusCode)
	}
	r, v = o.call(t, "POST", path+"/policy", body, csrf, nil)
	if r.StatusCode != 200 || v["revision"] != float64(1) || len(v["incidents"].([]any)) != 0 {
		t.Fatal("enable baseline", r.StatusCode, v)
	}
	if r, _ = o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("POST replay", r.StatusCode)
	}
	advanceEventWatch(f, "11")
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["status"] != "matched" || len(v["incidents"].([]any)) != 1 {
		t.Fatal(r.StatusCode, v)
	}
	incident := v["incidents"].([]any)[0].(map[string]any)
	if incident["countLowerBound"] != float64(1) {
		t.Fatal(incident)
	}
	raw, _ := json.Marshal(v)
	for _, forbidden := range []string{"recordId", "invitationId", "certificateHash", "eventData", "message", "recovered"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private/wrong semantics", forbidden)
		}
	}
	review := map[string]any{"requestId": "eventrequest_" + strings.Repeat("b", 32), "expectedRevision": 1, "sourceToken": windowseventwatch.SourceToken(f.input), "incidentId": incident["id"]}
	r, v = o.call(t, "POST", path+"/review", review, csrf, nil)
	if r.StatusCode != 200 || v["revision"] != float64(2) || v["incidents"].([]any)[0].(map[string]any)["reviewedAt"] == nil {
		t.Fatal(r.StatusCode, v)
	}
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || len(v["incidents"].([]any)) != 1 {
		t.Fatal("review reopened duplicate", r.StatusCode, v)
	}
	alarms, e := o.app.store.HealthStates(context.Background())
	if e != nil || len(alarms) != 0 {
		t.Fatal("modified Linux health", e)
	}
}
func TestWindowsEventWatchAPISourceIsolationAndPrivateExpiry(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installEventWatchFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	path := "/api/devices/" + f.input.Source.DeviceID + "/windows-event-watches"
	body := eventWatchPolicyBody(f)
	if r, v := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	advanceEventWatch(f, "11")
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.viewMismatch = true
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 409 {
		t.Fatal("torn source accepted", r.StatusCode)
	}
	f.viewMismatch = false
	f.now = f.now.Add(121 * time.Second)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["source"].(map[string]any)["available"] != false || v["status"] != "unknown" || len(v["source"].(map[string]any)["choices"].([]any)) != 0 {
		t.Fatal("stale source renewed", r.StatusCode, v)
	}
	f.input.Events.GrantID = strings.Repeat("1", 32)
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["canManage"] != false || len(v["incidents"].([]any)) != 0 || len(v["policy"].(map[string]any)["selectors"].([]any)) != 0 {
		t.Fatal("replacement leaked", r.StatusCode, v)
	}
	f.input.Events = nil
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || len(v["incidents"].([]any)) != 0 {
		t.Fatal("header grant missing leaked", r.StatusCode, v)
	}
	f.input.Source.Authorized = false
	if r, _ = o.call(t, "GET", path, nil, "", nil); r.StatusCode != 404 {
		t.Fatal("revoked leaked", r.StatusCode)
	}
}
func TestWindowsEventWatchAPIFinalLeaseRollsBack(t *testing.T) {
	for _, stop := range []int{2, 3, 4} {
		t.Run(string(rune('0'+stop)), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installEventWatchFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			path := "/api/devices/" + f.input.Source.DeviceID + "/windows-event-watches/policy"
			f.lease = func(n int) {
				if n == stop {
					f.input.Source.Authorized = false
				}
			}
			r, v := o.call(t, "POST", path, eventWatchPolicyBody(f), csrf, nil)
			if r.StatusCode == 200 {
				t.Fatal("revocation accepted", v)
			}
			records, e := o.app.store.WindowsEventWatchRecords(context.Background())
			if e != nil || len(records) != 0 {
				t.Fatal("expired authority wrote", e, records)
			}
		})
	}
}
func TestWindowsEventWatchBackgroundDefaultOffAndUnavailableRetention(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installEventWatchFixture(t, o)
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	records, _ := o.app.store.WindowsEventWatchRecords(context.Background())
	if len(records) != 0 {
		t.Fatal(records)
	}
	f.fail = true
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal("disabled monitor read source", e)
	}
	f.fail = false
	command := store.WindowsEventWatchCommand{RequestID: "eventrequest_" + strings.Repeat("a", 32), Operation: "policy", SourceToken: windowseventwatch.SourceToken(f.input), Enabled: true, Selectors: []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, RetentionAcknowledged: true}
	if _, e := m.store.UpdateWindowsEventWatch(context.Background(), f.input, &command, false, f.Now, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	advanceEventWatch(f, "11")
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(windowseventwatch.Retention)
	f.fail = true
	if e := m.evaluate(context.Background()); e == nil {
		t.Fatal("source outage not reported")
	}
	record, e := m.store.WindowsEventWatchRecord(context.Background(), f.input.Source.DeviceID)
	if e != nil || len(record.State.Incidents) != 0 || !record.State.Policy.Enabled {
		t.Fatal("unavailable source prevented bounded retention", e, record)
	}
}

func TestWindowsEventWatchViewEndsAtDerivedRetention(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installEventWatchFixture(t, o)
	ctx := context.Background()
	c := store.WindowsEventWatchCommand{RequestID: "eventrequest_" + strings.Repeat("a", 32), Operation: "policy", SourceToken: windowseventwatch.SourceToken(f.input), Enabled: true, Selectors: []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, RetentionAcknowledged: true}
	if _, e := m.store.UpdateWindowsEventWatch(ctx, f.input, &c, false, f.Now, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	advanceEventWatch(f, "11")
	if e := m.evaluate(ctx); e != nil {
		t.Fatal(e)
	}
	record, e := m.store.WindowsEventWatchRecord(ctx, f.input.Source.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	expiry := record.State.Incidents[0].LastReceivedAt.Add(windowseventwatch.Retention)
	f.now = expiry.Add(-time.Second)
	f.input.Source.ReceivedAt = f.now
	f.input.Source.Sequence++
	f.input.Events.CollectedAt = f.now
	v, e := eventWatchView(record, f.input, f.now, true)
	if e != nil || !v.ValidUntil.Equal(expiry) || len(v.Incidents) != 1 || v.Status != "unknown" {
		t.Fatal("derived expiry extended", e, v)
	}
	f.now = expiry
	v, e = eventWatchView(record, f.input, f.now, true)
	if e != nil || len(v.Incidents) != 0 {
		t.Fatal("expired history exposed", e, v)
	}
}

type fairEventWatchSource struct {
	fixtures map[string]*fixtureEventWatchSource
	now      time.Time
	slow     map[string]bool
	calls    []string
}

func (f *fairEventWatchSource) Now() time.Time { return f.now }
func (f *fairEventWatchSource) WindowsContactInputs(ctx context.Context, _ time.Time) ([]windowscontact.Input, error) {
	out := []windowscontact.Input{}
	for _, fixture := range f.fixtures {
		out = append(out, fixture.input.Source)
	}
	return out, ctx.Err()
}
func (f *fairEventWatchSource) WindowsInventoryView(ctx context.Context, id string, at time.Time) (enrollmentstore.WindowsInventoryView, error) {
	f.calls = append(f.calls, id)
	if f.slow[id] {
		<-ctx.Done()
		return enrollmentstore.WindowsInventoryView{}, ctx.Err()
	}
	return f.fixtures[id].WindowsInventoryView(ctx, id, at)
}
func (f *fairEventWatchSource) WithWindowsNotificationAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	return f.fixtures[in.DeviceID].WithWindowsNotificationAuthority(ctx, in, fn)
}
func TestWindowsEventWatchSlowDevicesCannotStarveLaterWatch(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, base := installEventWatchFixture(t, o)
	f := &fairEventWatchSource{fixtures: map[string]*fixtureEventWatchSource{}, slow: map[string]bool{}, now: base.now}
	ids := []string{}
	for _, letter := range []string{"a", "b", "c"} {
		fixture := *base
		events := *base.input.Events
		events.Channels = append([]windowseventhealth.Channel{}, events.Channels...)
		events.Channels[0].Rows = append([]windowseventhealth.Event{}, events.Channels[0].Rows...)
		fixture.input.Events = &events
		fixture.input.Source.DeviceID = "agent_" + strings.Repeat(letter, 32)
		id := fixture.input.Source.DeviceID
		ids = append(ids, id)
		f.fixtures[id] = &fixture
		f.slow[id] = letter != "c"
		command := store.WindowsEventWatchCommand{RequestID: "eventrequest_" + strings.Repeat(letter, 32), Operation: "policy", SourceToken: windowseventwatch.SourceToken(fixture.input), Enabled: true, Selectors: []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, RetentionAcknowledged: true}
		if _, e := m.store.UpdateWindowsEventWatch(context.Background(), fixture.input, &command, false, fixture.Now, func(time.Time) error { return nil }); e != nil {
			t.Fatal(e)
		}
		advanceEventWatch(&fixture, "11")
		f.now = fixture.now
	}
	m.source = f
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_ = m.evaluate(ctx)
		cancel()
	}
	record, e := m.store.WindowsEventWatchRecord(context.Background(), ids[2])
	if e != nil || len(record.State.Incidents) != 1 {
		t.Fatal("healthy later device starved", e, f.calls, record)
	}
	if len(f.calls) < 3 || f.calls[0] != ids[0] || f.calls[1] != ids[1] || f.calls[2] != ids[2] {
		t.Fatal("not resumed fairly", f.calls)
	}
}

func TestWindowsEventWatchRawViewBoundaryCannotBeExtended(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installEventWatchFixture(t, o)
	ctx := context.Background()
	c := store.WindowsEventWatchCommand{RequestID: "eventrequest_" + strings.Repeat("a", 32), Operation: "policy", SourceToken: windowseventwatch.SourceToken(f.input), Enabled: true, Selectors: []windowseventwatch.Selector{{Channel: "Application", Provider: "Fixture", EventID: 42, Level: 2}}, RetentionAcknowledged: true}
	if _, e := m.store.UpdateWindowsEventWatch(ctx, f.input, &c, false, f.Now, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	advanceEventWatch(f, "11")
	if e := m.evaluate(ctx); e != nil {
		t.Fatal(e)
	}
	record, e := m.store.WindowsEventWatchRecord(ctx, f.input.Source.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	expiry := f.input.Events.CollectedAt.Add(24 * time.Hour)
	v, e := eventWatchView(record, f.input, expiry.Add(-time.Nanosecond), true)
	if e != nil || !v.ValidUntil.Equal(expiry) || len(v.Incidents) != 1 {
		t.Fatal("raw view deadline extended", e, v)
	}
	v, e = eventWatchView(record, f.input, expiry, true)
	if e != nil || v.CanManage || len(v.Policy.Selectors) != 0 || len(v.Incidents) != 0 || v.Source.Available {
		t.Fatal("expired raw authority exposed history", e, v)
	}
}
