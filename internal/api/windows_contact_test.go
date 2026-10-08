package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/windowscontact"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureWindowsContactSource struct {
	now    time.Time
	inputs []windowscontact.Input
	err    error
	reads  int
	onRead func(int)
}

func (f *fixtureWindowsContactSource) Now() time.Time { return f.now }
func (f *fixtureWindowsContactSource) WindowsContactInputs(ctx context.Context, _ time.Time) ([]windowscontact.Input, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.reads++
	if f.onRead != nil {
		f.onRead(f.reads)
	}
	if f.err != nil {
		return nil, f.err
	}
	return append([]windowscontact.Input{}, f.inputs...), nil
}
func contactFixtureInput(at time.Time) windowscontact.Input {
	return windowscontact.Input{DeviceID: "agent_" + strings.Repeat("a", 32), Authorized: true, AuthorityUntil: at.Add(time.Hour), ReceivedAt: at, Sequence: 1, InvitationID: "invite_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64)}
}
func installContactFixture(t *testing.T, o operatorFixture) (*windowsContactMonitor, *fixtureWindowsContactSource) {
	t.Helper()
	at := time.Now().UTC().Round(0)
	f := &fixtureWindowsContactSource{now: at, inputs: []windowscontact.Input{contactFixtureInput(at)}}
	m, err := newWindowsContactMonitor(o.app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	o.app.windowsContact = m
	return m, f
}
func openContactFixture(t *testing.T, m *windowsContactMonitor, f *fixtureWindowsContactSource) {
	t.Helper()
	base := f.inputs[0].ReceivedAt
	for sec := 0; sec <= 210; sec += 30 {
		f.now = base.Add(time.Duration(sec) * time.Second)
		if err := m.evaluate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWindowsContactAuthenticatedReadOnlyAndAuthority(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installContactFixture(t, o)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-contact"
	if response, _ := o.call(t, "GET", path, nil, "", nil); response.StatusCode != 401 {
		t.Fatal("anonymous contact history readable")
	}
	o.login(t)
	before, err := o.app.store.WindowsContactStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response, view := o.call(t, "GET", path, nil, "", nil); response.StatusCode != 200 || view["status"] != "unknown" {
		t.Fatal("first read fabricated evaluation", response.StatusCode, view)
	}
	after, _ := o.app.store.WindowsContactStates(context.Background())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET created state")
	}
	openContactFixture(t, m, f)
	before, _ = o.app.store.WindowsContactStates(context.Background())
	for i := 0; i < 2; i++ {
		response, view := o.call(t, "GET", path, nil, "", nil)
		if response.StatusCode != 200 || view["status"] != "overdue" || len(view["incidents"].([]any)) != 1 {
			t.Fatal("durable contact history unavailable", response.StatusCode, view)
		}
		raw, _ := json.Marshal(view)
		for _, private := range []string{"certificateHash", "invitationId", "epoch", "offline", "filesystem"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("wrong scope in public contact view", private)
			}
		}
	}
	after, _ = o.app.store.WindowsContactStates(context.Background())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET mutated evaluation or history")
	}
	for _, suffix := range []string{"", "/acknowledge", "/maintenance", "/services"} {
		if response, _ := o.call(t, "POST", path+suffix, map[string]any{}, "", nil); response.StatusCode == 200 {
			t.Fatal("contact mutation route exists", suffix)
		}
	}
	if response, _ := o.call(t, "GET", strings.Replace(path, strings.Repeat("a", 32), strings.Repeat("d", 32), 1), nil, "", nil); response.StatusCode != 404 {
		t.Fatal("unknown identity returned history")
	}
	f.inputs[0].Authorized = false
	if response, _ := o.call(t, "GET", path, nil, "", nil); response.StatusCode != 404 {
		t.Fatal("revoked identity returned history")
	}
	health, err := o.app.store.HealthStates(context.Background())
	if err != nil || len(health) != 0 {
		t.Fatal("Windows path wrote Linux health state", err)
	}
	analyses, err := o.app.store.HealthAnalyses(context.Background(), f.inputs[0].DeviceID)
	if err != nil || len(analyses) != 0 {
		t.Fatal("Windows path created analyses", err)
	}
}

func TestWindowsContactFinalAuthoritySessionAndTimeRecheck(t *testing.T) {
	for _, kind := range []string{"revoked", "certificate-changed", "certificate-expired", "source-error", "clock-rollback", "slow-read", "session-revoked"} {
		t.Run(kind, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installContactFixture(t, o)
			openContactFixture(t, m, f)
			login, _ := o.login(t)
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch kind {
				case "revoked":
					f.inputs[0].Authorized = false
				case "certificate-changed":
					f.inputs[0].CertificateHash = strings.Repeat("d", 64)
				case "certificate-expired":
					f.now = f.inputs[0].AuthorityUntil
				case "source-error":
					f.err = errors.New("synthetic source unavailable")
				case "clock-rollback":
					f.now = f.now.Add(-time.Second)
				case "slow-read":
					f.now = f.now.Add(6 * time.Second)
				case "session-revoked":
					o.server.Config.Handler.(*operatorHandler).auth.Logout(login.Cookies()[0].Value)
				}
			}
			response, view := o.call(t, "GET", "/api/devices/"+f.inputs[0].DeviceID+"/windows-contact", nil, "", nil)
			if response.StatusCode == 200 || view["incidents"] != nil || view["lastAcceptedAt"] != nil {
				t.Fatal("changed authority/time released history", response.StatusCode, view)
			}
		})
	}
}

func TestWindowsContactReplacementIdentityCannotReadRetainedHistory(t *testing.T) {
	for _, kind := range []string{"certificate", "invitation"} {
		t.Run(kind, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installContactFixture(t, o)
			openContactFixture(t, m, f)
			o.login(t)
			before, err := o.app.store.WindowsContactState(context.Background(), f.inputs[0].DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "certificate" {
				f.inputs[0].CertificateHash = strings.Repeat("d", 64)
			} else {
				f.inputs[0].InvitationID = "invite_" + strings.Repeat("d", 32)
			}
			response, view := o.call(t, "GET", "/api/devices/"+f.inputs[0].DeviceID+"/windows-contact", nil, "", nil)
			if response.StatusCode != 409 || view["incidents"] != nil || view["lastAcceptedAt"] != nil || view["evaluatedAt"] != nil {
				t.Fatal("replacement identity received retained history", response.StatusCode, view)
			}
			if err := m.evaluate(context.Background()); err == nil {
				t.Fatal("replacement identity rebound historical store")
			}
			after, err := o.app.store.WindowsContactState(context.Background(), f.inputs[0].DeviceID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("replacement identity changed retained history", err)
			}
		})
	}
}

func TestWindowsContactMonitorFailureRestartAndCancellation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installContactFixture(t, o)
	openContactFixture(t, m, f)
	ctx := context.Background()
	id := f.inputs[0].DeviceID
	before, err := o.app.store.WindowsContactState(ctx, id)
	if err != nil || len(before.Incidents) != 1 {
		t.Fatal("monitor did not persist without browser", err)
	}
	f.err = errors.New("synthetic source failure")
	if m.evaluate(ctx) == nil || m.ready || m.epoch != "" {
		t.Fatal("source error preserved current continuity")
	}
	after, _ := o.app.store.WindowsContactState(ctx, id)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source error modified durable history")
	}
	f.err = nil
	o.login(t)
	path := "/api/devices/" + id + "/windows-contact"
	response, view := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || view["status"] != "unknown" || len(view["incidents"].([]any)) != 1 {
		t.Fatal("failure did not retain historical/unknown distinction", response.StatusCode, view)
	}
	restarted, err := newWindowsContactMonitor(o.app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	o.app.windowsContact = restarted
	response, view = o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || view["status"] != "unknown" || len(view["incidents"].([]any)) != 1 {
		t.Fatal("restart fabricated live continuity", response.StatusCode, view)
	}
	f.now = f.now.Add(30 * time.Second)
	f.inputs[0].ReceivedAt = f.now
	f.inputs[0].Sequence = 2
	if err := restarted.evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(30 * time.Second)
	if err := restarted.evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	still, _ := o.app.store.WindowsContactState(ctx, id)
	if still.Incidents[0].ResolvedAt != nil {
		t.Fatal("recovery confirmed before minute")
	}
	f.now = f.now.Add(30 * time.Second)
	if err := restarted.evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, _ := o.app.store.WindowsContactState(ctx, id)
	if recovered.Incidents[0].ResolvedAt == nil || recovered.Incidents[0].ID != before.Incidents[0].ID {
		t.Fatal("contact did not recover original durable incident")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := restarted.evaluate(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	if err := o.app.RunWindowsContactMonitor(canceled, nil); err != nil {
		t.Fatal("canceled monitor did not stop", err)
	}
}

func TestWindowsContactMonitorRejectsDuplicateIDsBeforeWrites(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installContactFixture(t, o)
	f.inputs = append(f.inputs, f.inputs[0])
	if err := m.evaluate(context.Background()); err == nil {
		t.Fatal("duplicate device inputs accepted")
	}
	states, err := o.app.store.WindowsContactStates(context.Background())
	if err != nil || len(states) != 0 {
		t.Fatal("invalid source partially wrote state", err)
	}
}
