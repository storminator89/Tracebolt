package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

const completeNotificationsPath = "/api/fleet/windows-notifications/complete"

// Reuses recorder-only fixtures, temporary SQLite and invented enrollment/source
// data. Settings construct an inert worker but Run/Step is never called on it.
func completeNotificationHandlerFixture(t *testing.T, opened bool) (*operatorHandler, *completeInboxFixture, operatorRequest, alarmdelivery.Binding) {
	t.Helper()
	var h *operatorHandler
	var f *completeInboxFixture
	var op operatorRequest
	if opened {
		h, f, op = completeInboxHandlerFixture(t)
	} else {
		var base *completeHealthFixture
		h, base, op, _ = completeHealthHandlerFixture(t)
		f = &completeInboxFixture{completeHealthFixture: base, currentLeaf: strings.Repeat("c", 64)}
		h.app.windowsCapacity.source = f
		path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
		if w := completeServiceRequest(h, op, "POST", path, completeServiceBody(base)); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "fixture-config.json")
	raw, _ := json.Marshal(map[string]any{"schemaVersion": alarmdelivery.ConfigSchemaVersion, "enabled": true, "payloadSharingAcknowledged": true, "managerInstanceId": "manager-fixture", "profile": "tls", "destinationId": "fixture", "generation": "one", "endpoint": "https://receiver.example.test/fixture-only", "bearerTokenFile": ""})
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	config, e := alarmdelivery.Load(path, "manager-fixture", "tls")
	if e != nil {
		t.Fatal(e)
	}
	settings, e := alarmdelivery.NewSettings(h.app.store, dir, "manager-fixture", "tls", config)
	if e != nil {
		t.Fatal(e)
	}
	h.alarmSettings = settings
	return h, f, op, config.Binding()
}
func completeNotificationNamedOperator(t *testing.T, origin string) operatorRequest {
	t.Helper()
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAlarms}}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	return operatorRequest{session: session, origin: origin, active: func() bool { _, e := auth.Lookup(session.Token); return e == nil }}
}

func completeNotificationRequest(h *operatorHandler, op operatorRequest, method, path string, body any, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, "https://maintenance.invalid"+path, reader)
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	for _, change := range changes {
		change(r)
	}
	w := httptest.NewRecorder()
	h.windowsNotificationsAPI(w, r)
	return w
}
func completeNotificationRead(t *testing.T, h *operatorHandler, op operatorRequest) windowsCompleteNotificationView {
	t.Helper()
	w := completeNotificationRequest(h, op, "GET", completeNotificationsPath, nil)
	var view windowsCompleteNotificationView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return view
}
func completeNotificationBody(view windowsCompleteNotificationView) map[string]any {
	row := view.Targets[0]
	return map[string]any{"key": row.Key, "revision": row.Revision, "enabled": true, "destinationBinding": view.DestinationBinding, "payloadAcknowledged": true}
}
func advanceCompleteNotificationSample(f *completeInboxFixture, at time.Time, state string) {
	f.now = at
	p := &f.sampleComplete.Source
	p.Sequence++
	p.CapturedAt = at
	p.CaptureFinishedAt = at
	p.ReceivedAt = at
	p.ExpiresAt = at.Add(24 * time.Hour)
	p.GenerationID, _ = windowsfullservices.GenerationID(f.inputs[0].DeviceID, p.GrantID, p.Sequence)
	f.sampleComplete.Rows[0].State = &state
}
func TestCompleteNotificationsRecorderOptInNoBackfillAndScopeReplacement(t *testing.T) {
	h, f, op, _ := completeNotificationHandlerFixture(t, true)
	ctx := context.Background()
	before, e := h.app.store.WindowsServiceState(ctx, f.inputs[0].DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	beforeRaw, _ := windowsservicehealth.Encode(before)
	initial := completeNotificationRead(t, h, op)
	if len(initial.Targets) != 1 || !initial.Targets[0].Actionable || initial.Targets[0].Enabled || initial.Targets[0].Effective || initial.Targets[0].Revision != 0 || !initial.DeliveryEnabled || len(initial.Targets[0].Services[0]) <= 256 {
		t.Fatal(initial)
	}
	body := completeNotificationBody(initial)
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	approved := completeNotificationRead(t, h, op)
	if !approved.Targets[0].Effective || approved.Counts.Queued != 0 || approved.Targets[0].Revision != 1 {
		t.Fatal("implicit backfill or lost approval", approved)
	}
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", body); w.Code != 409 {
		t.Fatal("replayed approval", w.Code)
	}
	snap, e := h.app.store.WindowsNotifications(ctx)
	if e != nil || len(snap.Policies) != 0 || len(snap.CompletePolicies) != 1 {
		t.Fatal("legacy approval changed", snap, e)
	}
	after, e := h.app.store.WindowsServiceState(ctx, f.inputs[0].DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	afterRaw, _ := windowsservicehealth.Encode(after)
	if !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatal("consent altered incident truth")
	}
	// A changed health revision needs a separate review even under the same grant.
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/complete/policy"
	added := f.sampleComplete.Rows[0]
	added.Name = "AddedService"
	f.sampleComplete.Rows = append([]windowsfullservices.Row{added}, f.sampleComplete.Rows...)
	policy := map[string]any{"enabled": true, "services": append([]string{"AddedService"}, initial.Targets[0].Services...), "expectedRevision": before.Policy.Revision, "source": f.sampleComplete.Source}
	if w := completeServiceRequest(h, op, "POST", path, policy); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	changed := completeNotificationRead(t, h, op)
	if changed.Targets[0].Key == approved.Targets[0].Key || changed.Targets[0].Revision != 1 || !changed.Targets[0].Enabled || changed.Targets[0].Effective {
		t.Fatal("health revision inherited consent", changed)
	}
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", completeNotificationBody(changed)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	// Fresh source absence never grants approval, but retained approval can be stopped.
	f.sampleComplete = nil
	unknown := completeNotificationRead(t, h, op)
	if unknown.Targets[0].Actionable || unknown.Targets[0].Effective {
		t.Fatal("missing source actionable")
	}
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", completeNotificationBody(unknown)); w.Code != 409 {
		t.Fatal("unknown enabled", w.Code)
	}
	disable := map[string]any{"key": unknown.Targets[0].Key, "revision": unknown.Targets[0].Revision, "enabled": false, "destinationBinding": "", "payloadAcknowledged": false}
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", disable); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	f.inputs[0].CertificateHash = strings.Repeat("e", 64)
	if v := completeNotificationRead(t, h, op); len(v.Targets) != 0 {
		t.Fatal("replacement inherited private scope", v)
	}
}

func TestCompleteNotificationsRecorderClosedRequestsAndFinalLease(t *testing.T) {
	for _, mode := range []string{"csrf", "origin", "extra", "consent", "named", "query", "generation", "grant", "current-leaf", "source-expiry", "session", "clock"} {
		t.Run(mode, func(t *testing.T) {
			h, f, op, _ := completeNotificationHandlerFixture(t, false)
			if mode == "source-expiry" {
				f.now = f.sampleComplete.Source.CapturedAt.Add(299 * time.Second)
			}
			view := completeNotificationRead(t, h, op)
			body := completeNotificationBody(view)
			if mode == "extra" {
				body["extra"] = true
			}
			if mode == "consent" {
				body["payloadAcknowledged"] = false
			}
			if mode == "named" {
				op = completeNotificationNamedOperator(t, op.origin)
			}
			live := true
			op.active = func() bool { return live }
			f.onGuard = func(n int) {
				if n != 4 {
					return
				}
				switch mode {
				case "generation":
					f.sampleComplete.Source.ManifestSHA256 = strings.Repeat("e", 64)
				case "grant":
					f.sampleComplete.Source.GrantRevision++
				case "current-leaf":
					f.currentLeaf = strings.Repeat("d", 64)
				case "source-expiry":
					f.now = f.now.Add(2 * time.Second)
				case "session":
					live = false
				case "clock":
					f.now = f.now.Add(-time.Second)
				}
			}
			w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", body, func(r *http.Request) {
				switch mode {
				case "csrf":
					r.Header.Del("X-CSRF-Token")
				case "origin":
					r.Header.Set("Origin", "https://other.invalid")
				case "query":
					r.URL.RawQuery = "extra=1"
				}
			})
			if w.Code == 200 {
				t.Fatal("unsafe request committed", mode)
			}
			snapshot, e := h.app.store.WindowsNotifications(context.Background())
			if e != nil || len(snapshot.CompletePolicies) != 0 {
				t.Fatal("failed guard persisted consent", e)
			}
		})
	}
	h, _, op, _ := completeNotificationHandlerFixture(t, false)
	for _, test := range []struct {
		method, path string
		body         any
		code         int
	}{{"GET", completeNotificationsPath, map[string]any{}, 400}, {"GET", completeNotificationsPath + "?", nil, 400}, {"POST", completeNotificationsPath, nil, 405}, {"GET", completeNotificationsPath + "/other", nil, 404}} {
		if w := completeNotificationRequest(h, op, test.method, test.path, test.body); w.Code != test.code {
			t.Fatal(test, w.Code)
		}
	}
	op = completeNotificationNamedOperator(t, op.origin)
	if w := completeNotificationRequest(h, op, "GET", completeNotificationsPath, nil); w.Code != 200 {
		t.Fatal("named read denied", w.Code)
	}
}

func TestCompleteNotificationsQueueAdapterCompleteLeaseAndOutcome(t *testing.T) {
	h, f, op, binding := completeNotificationHandlerFixture(t, false)
	ctx := context.Background()
	q := NewWindowsNotificationQueue(h.app.store, f)
	view := completeNotificationRead(t, h, op)
	if w := completeNotificationRequest(h, op, "POST", completeNotificationsPath+"/policy", completeNotificationBody(view)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	// Only direct durable claim/completion is exercised; no transport is run.
	start := f.now
	for i := 0; i <= 4; i++ {
		f.now = start.Add(time.Duration(i) * 30 * time.Second)
		if i == 4 {
			advanceCompleteNotificationSample(f, f.now, "stopped")
		}
		if e := h.app.windowsCapacity.evaluate(ctx); e != nil {
			t.Fatal(e)
		}
	}
	snap, e := h.app.store.WindowsNotifications(ctx)
	if e != nil || snap.Counts.Queued != 1 {
		t.Fatal(snap, e)
	}
	candidate, e := q.NextWindowsNotification(ctx, binding, f.now)
	if e != nil || candidate == nil || candidate.CompleteTarget == nil {
		t.Fatal(candidate, e)
	}
	// The complete adapter must never use the inbox-ack lease.
	f.onIncidentGuard = func(int) { t.Fatal("acknowledgement lease used for dispatch") }
	attempt, e := q.ClaimAlarm(ctx, binding, f.now)
	if e != nil || attempt == nil || attempt.Payload.SchemaVersion != store.WindowsCompleteNotificationSchema || attempt.Payload.Rule != "windows-service-complete" {
		t.Fatal(attempt, e)
	}
	if e = q.CompleteAlarm(ctx, binding, *attempt, alarmdelivery.Result{Outcome: alarmdelivery.Accepted, Code: "provider_accepted"}, f.now); e != nil {
		t.Fatal(e)
	}
	snap, e = h.app.store.WindowsNotifications(ctx)
	if e != nil || snap.Counts.ProviderAccepted != 1 {
		t.Fatal(snap, e)
	}
	linux, e := h.app.store.AlarmStatus(ctx)
	if e != nil || linux.ProviderAccepted != 0 {
		t.Fatal("complete outcome entered Linux", linux, e)
	}
}

func TestCompleteNotificationsWireFixture(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(at)
	in.CurrentLeaf = strings.Repeat("c", 64)
	name := strings.Repeat("界", 100)
	state := "stopped"
	p := windowsservicehealth.Provenance{Kind: windowsservicehealth.CompleteSourceKind, GrantID: strings.Repeat("a", 32), GrantRevision: 1, ManifestSHA256: strings.Repeat("b", 64), Sequence: 1, CapturedAt: at, CaptureFinishedAt: at, ReceivedAt: at, ExpiresAt: at.Add(24 * time.Hour), RowCount: 2051}
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
	in.Services.Complete = &windowsservicehealth.CompleteSample{Source: p, Rows: []windowsfullservices.Row{{Name: name, State: &state, StateQuality: "observed", DisplayNameQuality: "unavailable", PIDQuality: "unavailable"}}}
	health := windowsservicehealth.NewComplete()
	if e := health.Configure(windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: true, Selection: &p}, true, []string{name}, 0, at); e != nil {
		t.Fatal(e)
	}
	target := store.WindowsCompleteNotificationTarget{WindowsMaintenanceTarget: maintenanceTarget(in, "service-complete"), Source: p.Binding(), HealthPolicyRevision: health.Policy.Revision}
	destination := alarmdelivery.SourceDestination{Host: "receiver.example.test", Binding: strings.Repeat("a", 64), Enabled: true}
	snapshot := store.WindowsNotificationSnapshot{Binding: destination.Binding, DeliveryEnabled: true, CompletePolicies: []store.WindowsCompleteNotificationPolicy{{Version: 2, Target: target, Revision: 1, Enabled: true, Binding: destination.Binding, ChangedAt: at}}, Counts: store.AlarmStatus{ProviderAccepted: 1, Suppressed: 1}}
	view, _, e := projectWindowsCompleteNotifications(snapshot, nil, map[string]windowsservicehealth.State{in.DeviceID: health}, map[string]windowscapacity.Input{in.DeviceID: in}, destination, at)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.MarshalIndent(view, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := "../../tests/fixtures/windows-complete-notifications-view.json"
	if os.Getenv("TRACEBOLT_WRITE_COMPLETE_NOTIFICATION_FIXTURE") == "1" {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	existing, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(existing, raw) {
		t.Fatal("complete notification Go/TypeScript fixture changed; review regeneration", e)
	}
}
