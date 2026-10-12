package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
)

func incidentInboxFixture(t *testing.T, o operatorFixture) (*windowsCapacityMonitor, *fixtureWindowsCapacitySource) {
	t.Helper()
	m, f := installCapacityFixture(t, o)
	f.inputs[0].CPU = f.inputs[0].Disk
	f.inputs[0].Memory = f.inputs[0].Disk
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		if _, e := m.store.ConfigureWindowsResource(context.Background(), f.inputs[0], kind, true, 90, 0, f.now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := m.store.ConfigureWindowsCapacity(context.Background(), f.inputs[0], true, 90, 0, f.now); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 3; n++ {
		if n > 0 {
			advanceCapacity(f, 30, 95)
			f.inputs[0].CPU = f.inputs[0].Disk
			f.inputs[0].Memory = f.inputs[0].Disk
		}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	return m, f
}
func readInbox(t *testing.T, o operatorFixture, path string) windowsInboxView {
	t.Helper()
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	raw, _ := json.Marshal(v)
	var view windowsInboxView
	if e := json.Unmarshal(raw, &view); e != nil {
		t.Fatal(e)
	}
	return view
}

const inboxPath = "/api/fleet/windows-incidents"

func TestWindowsIncidentInboxReadOnlyPagingAcknowledgementAndDomains(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	if r, _ := o.call(t, "GET", inboxPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous inbox")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before, e := m.store.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	view := readInbox(t, o, inboxPath+"?limit=2")
	after, _ := m.store.WindowsIncidentSnapshot(context.Background())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET mutated history")
	}
	if view.Total != 3 || view.Counts.Active != 3 || len(view.Items) != 2 || view.NextOffset == nil || *view.NextOffset != 2 || view.Coverage.Devices != 1 {
		t.Fatal("bounded page", view)
	}
	last := readInbox(t, o, inboxPath+"?limit=2&offset=2")
	if len(last.Items) != 1 || last.NextOffset != nil || last.Items[0].Key == view.Items[0].Key || last.Items[0].Key == view.Items[1].Key {
		t.Fatal("page duplication")
	}
	all := readInbox(t, o, inboxPath+"?scope=all")
	keys := map[string]bool{}
	id := all.Items[0].IncidentID
	for _, item := range all.Items {
		if item.IncidentID != id || keys[item.Key] {
			t.Fatal("cross-domain collision")
		}
		keys[item.Key] = true
	}
	target := all.Items[0]
	body := map[string]any{"key": target.Key}
	if r, _ := o.call(t, "POST", inboxPath+"/acknowledge", body, "", nil); r.StatusCode != 403 {
		t.Fatal("no csrf")
	}
	if r, _ := o.call(t, "POST", inboxPath+"/acknowledge", body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("cross origin")
	}
	r, ack := o.call(t, "POST", inboxPath+"/acknowledge", body, csrf, nil)
	if r.StatusCode != 200 || ack["key"] != target.Key {
		t.Fatal(r.StatusCode, ack)
	}
	r, again := o.call(t, "POST", inboxPath+"/acknowledge", body, csrf, nil)
	if r.StatusCode != 200 || ack["acknowledgedAt"] != again["acknowledgedAt"] {
		t.Fatal("idempotent acknowledgement", r.StatusCode, again)
	}
	acknowledged := readInbox(t, o, inboxPath+"?ack=acknowledged")
	if acknowledged.Total != 1 || acknowledged.Counts.Active != 3 || acknowledged.Items[0].ResolvedAt != nil || acknowledged.Items[0].Key != target.Key {
		t.Fatal("ack resolved or collided")
	}
	unseen := readInbox(t, o, inboxPath+"?ack=unacknowledged")
	if unseen.Total != 2 {
		t.Fatal("unacknowledged filter")
	}
	// A changed accepted tuple removes confidence while preserving the episode and seen marker.
	advanceCapacity(f, 1, 95)
	unknown := readInbox(t, o, inboxPath+"?ack=acknowledged")
	if unknown.Items[0].Status != "unknown" || unknown.Items[0].AcknowledgedAt == nil {
		t.Fatal("GET fabricated freshness")
	}
	after, _ = m.store.WindowsIncidentSnapshot(context.Background())
	after.Acknowledgements = before.Acknowledgements
	if !reflect.DeepEqual(before, after) {
		t.Fatal("ack changed policy/evidence/episode")
	}
	raw, _ := json.Marshal(all)
	for _, private := range []string{"invitationId", "certificateHash", "sequenceFloor", "epoch"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private binding leak", private)
		}
	}
}
func TestWindowsIncidentInboxAuthoritySessionAndExactRequests(t *testing.T) {
	for _, change := range []string{"revoked", "replacement", "expired", "session"} {
		t.Run(change, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := incidentInboxFixture(t, o)
			loginResponse, login := o.login(t)
			view := readInbox(t, o, inboxPath)
			key := view.Items[0].Key
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch change {
				case "revoked":
					f.inputs[0].Authorized = false
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("e", 64)
				case "expired":
					f.inputs[0].AuthorityUntil = f.now
				case "session":
					auth := o.server.Config.Handler.(*operatorHandler).auth
					token := loginResponse.Cookies()[0].Value
					go auth.Logout(token)
					deadline := time.Now().Add(time.Second)
					for time.Now().Before(deadline) {
						if _, err := auth.Lookup(token); err != nil {
							break
						}
						time.Sleep(time.Millisecond)
					}
				}
			}
			r, _ := o.call(t, "POST", inboxPath+"/acknowledge", map[string]any{"key": key}, login["csrfToken"].(string), nil)
			if r.StatusCode == 200 {
				t.Fatal("changed authority/session acknowledged")
			}
			snapshot, e := m.store.WindowsIncidentSnapshot(context.Background())
			if e != nil || len(snapshot.Acknowledgements) != 0 {
				t.Fatal("failed admission wrote ack", e)
			}
		})
	}
	o := newOperatorFixture(t, time.Hour)
	_, _ = incidentInboxFixture(t, o)
	_, login := o.login(t)
	for _, query := range []string{"?scope=bogus", "?limit=51", "?offset=12501", "?limit=01", "?ack=all&ack=all", "?unknown=x", "?scope=all;limit=2", "?"} {
		if r, _ := o.call(t, "GET", inboxPath+query, nil, "", nil); r.StatusCode == 200 {
			t.Fatal("ambiguous query accepted", query)
		}
	}
	for _, body := range []map[string]any{{"key": strings.Repeat("a", 64), "domain": "cpu"}, {"key": strings.Repeat("a", 64)}, {"key": "bad"}} {
		if r, _ := o.call(t, "POST", inboxPath+"/acknowledge", body, login["csrfToken"].(string), nil); r.StatusCode == 200 {
			t.Fatal("unknown target/body accepted")
		}
	}
}
func TestWindowsIncidentInboxNamedReadOnlyAndUnavailableCoverage(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, f := incidentInboxFixture(t, o)
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	view := readInbox(t, o, inboxPath)
	if r, _ := o.call(t, "POST", inboxPath+"/acknowledge", map[string]any{"key": view.Items[0].Key}, login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named reader mutated ack")
	}
	f.inputs[0].Authorized = false
	view = readInbox(t, o, inboxPath)
	if len(view.Items) != 0 || view.Coverage.UnavailableDevices != 1 || view.Coverage.Devices != 0 {
		t.Fatal("unavailable history disclosed", view)
	}
}
func TestWindowsIncidentInboxPolicyClosureRecentAndClockGuards(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	_, login := o.login(t)
	if _, e := m.store.ConfigureWindowsCapacity(context.Background(), f.inputs[0], false, 90, 1, f.now); e != nil {
		t.Fatal(e)
	}
	resolved := readInbox(t, o, inboxPath+"?scope=resolved")
	if resolved.Total != 1 || resolved.Items[0].ClosedReason != "policy-changed" || resolved.Items[0].RecoveryCollectedAt != nil {
		t.Fatal("policy closure called recovery")
	}
	recent := readInbox(t, o, inboxPath+"?scope=recent")
	if recent.Total != 3 {
		t.Fatal("recent scope")
	}
	key := recent.Items[0].Key
	start := f.now
	expiry := start.Add(time.Second)
	f.inputs[0].AuthorityUntil = expiry
	for _, rejectAt := range []int{5, 6} {
		clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
		clock.transition = func(n int) time.Time {
			if n >= rejectAt {
				return expiry
			}
			return start
		}
		m.source = clock
		if r, _ := o.call(t, "POST", inboxPath+"/acknowledge", map[string]any{"key": key}, login["csrfToken"].(string), nil); r.StatusCode == 200 {
			t.Fatal("transaction expiry accepted")
		}
		snapshot, e := m.store.WindowsIncidentSnapshot(context.Background())
		if e != nil || len(snapshot.Acknowledgements) != 0 {
			t.Fatal("transaction expiry wrote ack", e)
		}
	}
}

// Keep the full 12,500-row fleet bound explicit instead of borrowing Linux's cap.
func TestWindowsIncidentInboxProjectionBound(t *testing.T) {
	if store.MaxWindowsInboxIncidents != 12500 {
		t.Fatal("Windows retained-domain bound changed")
	}
}

func (f *fixtureWindowsCapacitySource) WithWindowsIncidentAuthority(ctx context.Context, expected windowscontact.Input, fn func(func(time.Time) error) error) error {
	guard := func(minimum time.Time) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, in := range f.inputs {
			if in.DeviceID == expected.DeviceID && in.Authorized && in.InvitationID == expected.InvitationID && in.CertificateHash == expected.CertificateHash && in.AuthorityUntil.Equal(expected.AuthorityUntil) && !f.now.Before(minimum) && f.now.Before(in.AuthorityUntil) {
				return nil
			}
		}
		return store.ErrWindowsIncident
	}
	if err := guard(f.now); err != nil {
		return err
	}
	return fn(guard)
}

func TestWindowsIncidentInboxStatusDeadlineUsesCurrentEvidence(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	_, _ = o.login(t)
	// The current metric remains 119 seconds old while a fresh evaluation still
	// occurs. Current confidence expires in one second, not 120 after evaluation.
	f.now = f.now.Add(119 * time.Second)
	// Avoid a monitor gap: direct epoch-qualified stored view uses the same
	// original observation. An actual monitor gap itself produces unknown.
	state, e := m.store.WindowsCapacityState(context.Background(), f.inputs[0].DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	state.EvaluatedAt = &f.now
	snapshot, e := m.store.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	snapshot.Capacities[state.DeviceID] = state
	view, e := projectWindowsInbox(snapshot, map[string]windowscapacity.Input{f.inputs[0].DeviceID: f.inputs[0]}, f.now, "", m.epoch, windowsInboxQuery{Scope: "all", Ack: "all", Limit: 25})
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range view.Items {
		if item.Domain == "disk" {
			if item.Status != "pressure" || item.StatusValidUntil == nil || item.StatusValidUntil.Sub(f.now) != time.Second {
				t.Fatal("receipt/evaluation refreshed old source", item)
			}
			return
		}
	}
	t.Fatal("missing disk incident")
}

type windowsInboxDeadlineSource struct {
	*fixtureWindowsCapacitySource
	readsBounded, leaseBounded bool
}

func inboxContextBounded(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
}
func (f *windowsInboxDeadlineSource) WindowsCapacityInputs(ctx context.Context, at time.Time) ([]windowscapacity.Input, error) {
	f.readsBounded = inboxContextBounded(ctx)
	return f.fixtureWindowsCapacitySource.WindowsCapacityInputs(ctx, at)
}
func (f *windowsInboxDeadlineSource) WithWindowsIncidentAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	f.leaseBounded = inboxContextBounded(ctx)
	return f.fixtureWindowsCapacitySource.WithWindowsIncidentAuthority(ctx, in, fn)
}
func TestWindowsIncidentInboxRequestBoundsAuthorityLease(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	_, login := o.login(t)
	source := &windowsInboxDeadlineSource{fixtureWindowsCapacitySource: f}
	m.source = source
	view := readInbox(t, o, inboxPath)
	if !source.readsBounded {
		t.Fatal("inbox source lacks bounded request context")
	}
	if r, v := o.call(t, "POST", inboxPath+"/acknowledge", map[string]any{"key": view.Items[0].Key}, login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	if !source.leaseBounded {
		t.Fatal("enrollment lease can outlive request work bound")
	}
}
