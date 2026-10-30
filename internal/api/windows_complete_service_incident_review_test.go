package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

type completeReviewSource struct {
	*completeInboxFixture
	insideLease bool
}

func (f *completeReviewSource) WithWindowsCompleteIncidentAuthority(ctx context.Context, in windowsservicehealth.Input, fn func(func(time.Time) error) error) error {
	f.insideLease = true
	defer func() { f.insideLease = false }()
	// Match production pinAbsence: future evidence can become eligible while waiting.
	if in.Selection == nil && f.sampleComplete != nil && (f.sampleComplete.Source.CapturedAt.After(f.now) || f.sampleComplete.Source.ReceivedAt.After(f.now)) {
		return store.ErrWindowsIncident
	}
	return f.completeInboxFixture.WithWindowsCompleteIncidentAuthority(ctx, in, fn)
}

type completeReviewActions struct {
	windowsActionAPIFixture
	source                  *completeReviewSource
	views, expectedPreviews int
	onView                  func()
}

func (f *completeReviewActions) ViewAt(context.Context, string) (windowsactionjob.Record, time.Time, error) {
	if f.source.insideLease {
		panic("nested enrollment action read")
	}
	f.views++
	if f.onView != nil {
		f.onView()
	}
	f.at = f.source.now
	return f.record, f.at, nil
}
func (f *completeReviewActions) ViewExpectedAt(ctx context.Context, device, expected string) (windowsactionjob.Record, time.Time, error) {
	if windowsaction.ServiceReviewBindingDigest(f.record.Binding) != expected {
		return windowsactionjob.Record{}, f.at, windowsactionjob.ErrConflict
	}
	return f.ViewAt(ctx, device)
}
func (f *completeReviewActions) PreviewExpected(ctx context.Context, device, actor, target, operation, expected string) (windowsactionjob.Record, error) {
	f.expectedPreviews++
	if windowsaction.ServiceReviewBindingDigest(f.record.Binding) != expected {
		return windowsactionjob.Record{}, windowsactionjob.ErrConflict
	}
	return f.Preview(ctx, device, actor, target, operation)
}

type completeReviewFixture struct {
	serviceReviewAPIFixture
	full   *completeReviewSource
	action *completeReviewActions
	op     operatorRequest
}

// All fixtures below are direct recorder calls, in-memory source clocks and
// synthetic temporary SQLite state. No listener, broker/native control or grant.
func newCompleteReviewFixture(t *testing.T, name string) completeReviewFixture {
	t.Helper()
	h, base, op, _ := completeHealthHandlerFixture(t)
	f := &completeReviewSource{completeInboxFixture: &completeInboxFixture{completeHealthFixture: base, currentLeaf: strings.Repeat("c", 64)}}
	h.app.windowsCapacity.source = f
	// Freeze synthetic time so the Go/TypeScript wire contract is reproducible.
	f.now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for i := range f.inputs {
		f.inputs[i].ReceivedAt = f.now
		f.inputs[i].AuthorityUntil = f.now.Add(2 * time.Hour)
	}
	p := &f.sampleComplete.Source
	p.CapturedAt = f.now
	p.CaptureFinishedAt = f.now
	p.ReceivedAt = f.now
	p.ExpiresAt = f.now.Add(24 * time.Hour)
	f.sampleComplete.Rows[0].Name = name
	body := completeServiceBody(base)
	body["services"] = []string{name}
	if w := completeServiceRequest(h, op, "POST", "/api/devices/"+f.inputs[0].DeviceID+"/windows-services/complete/policy", body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	start := f.now
	for i := 0; i <= 4; i++ {
		f.now = start.Add(time.Duration(i) * 30 * time.Second)
		if i == 4 {
			p := &f.sampleComplete.Source
			p.Sequence++
			p.CapturedAt = f.now
			p.CaptureFinishedAt = f.now
			p.ReceivedAt = f.now
			p.ExpiresAt = f.now.Add(24 * time.Hour)
			p.GenerationID, _ = windowsfullservices.GenerationID(f.inputs[0].DeviceID, p.GrantID, p.Sequence)
		}
		if e := h.app.windowsCapacity.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	row := completeInboxRead(t, h, op, completeInboxPath).Items[0]
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsServiceControl}}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	target := name
	if !windowsaction.ValidTarget(target) {
		target = "FixtureService"
	}
	binding := windowsaction.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), EndpointID: row.DeviceID, KeyID: windowsaction.Digest(key.Public().(ed25519.PublicKey)), IncarnationDigest: "sha256:" + f.inputs[0].CertificateHash, InstallationID: "broker_" + strings.Repeat("2", 32), GrantDigest: windowsaction.Digest([]byte("grant")), Target: target, TargetDigest: windowsaction.Digest([]byte("config"))}
	record, e := windowsactionjob.New(binding, key.Public().(ed25519.PublicKey), f.now)
	if e != nil {
		t.Fatal(e)
	}
	if e = record.Report(windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: binding, CapturedAt: f.now.Unix(), Enabled: true}, f.now); e != nil {
		t.Fatal(e)
	}
	actions := &completeReviewActions{windowsActionAPIFixture: windowsActionAPIFixture{record: record, at: f.now, key: key}, source: f}
	h.auth = auth
	h.origin = "https://manager.invalid"
	h.authority = "manager.invalid"
	h.cookieName = operatorauth.CookieName
	h.windowsActions = actions
	h.app.lanOnly = true
	h.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: row.DeviceID, Platform: "windows"}}, nil }
	return completeReviewFixture{serviceReviewAPIFixture: serviceReviewAPIFixture{handler: h, session: session, key: row.Key, device: row.DeviceID}, full: f, action: actions, op: op}
}
func (f completeReviewFixture) path() string {
	return completeInboxPath + "/" + f.key + "/service-review"
}
func (f completeReviewFixture) read(t *testing.T) windowsCompleteServiceIncidentReviewView {
	t.Helper()
	code, raw := f.call(t, "GET", f.path(), nil, nil)
	var view windowsCompleteServiceIncidentReviewView
	if code != 200 || json.Unmarshal(raw, &view) != nil {
		t.Fatal(code, string(raw))
	}
	return view
}
func TestCompleteServiceIncidentReviewExactSourceAndManualPreview(t *testing.T) {
	f := newCompleteReviewFixture(t, "BeyondPreviewService")
	before, e := f.handler.app.store.WindowsCompleteIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	rawBefore, _ := json.Marshal(before)
	v := f.read(t)
	if v.SchemaVersion != "tracebolt.windows-service-incident-review.v2" || v.Incident.Key != f.key || v.Incident.OpeningSource == nil || v.Observation == nil || v.Observation.Source != f.full.sampleComplete.Source || v.Control.Status != "matched" || v.Control.Binding.IncarnationDigest != "sha256:"+f.full.inputs[0].CertificateHash {
		t.Fatal(v)
	}
	if v.Observation.Source.RowCount != 2051 || v.AuthorityExpiresAt != f.full.now.Add(time.Minute) || f.action.views != 1 || f.action.next != 0 || f.action.approvals != 0 {
		t.Fatal("read created work or lost full-source truth", v)
	}
	after, _ := f.handler.app.store.WindowsCompleteIncidentSnapshot(context.Background())
	rawAfter, _ := json.Marshal(after)
	if !bytes.Equal(rawBefore, rawAfter) {
		t.Fatal("review mutated source or seen history")
	}
	// Renewal changes active leaf only; original episode/control incarnation survives.
	f.full.currentLeaf = strings.Repeat("d", 64)
	f.full.inputs[0].AuthorityUntil = f.full.inputs[0].AuthorityUntil.Add(time.Hour)
	if renewed := f.read(t); renewed.Incident.Key != v.Incident.Key || renewed.Control.Status != "matched" {
		t.Fatal(renewed)
	}
	header := func(r *http.Request) { r.Header.Set(windowsServiceReviewHeader, *v.Control.BindingDigest) }
	if code, raw := f.call(t, "GET", f.actionPath(), nil, header); code != 200 {
		t.Fatal(code, string(raw))
	}
	body := map[string]string{"target": "BeyondPreviewService", "operation": "restart"}
	if code, raw := f.call(t, "POST", f.actionPath()+"/preview", body, header); code != 200 || f.action.next != 1 || f.action.approvals != 0 {
		t.Fatal(code, string(raw))
	}
	f.action.record.Binding.IncarnationDigest = windowsaction.Digest([]byte("replacement"))
	f.action.record.Preview = nil
	if code, raw := f.call(t, "POST", f.actionPath()+"/preview", body, header); code != 409 || f.action.next != 1 {
		t.Fatal("changed binding admitted", code, string(raw))
	}
	f.full.inputs[0].CertificateHash = strings.Repeat("e", 64)
	if code, _ := f.call(t, "GET", f.path(), nil, nil); code != 409 {
		t.Fatal("replacement inherited review", code)
	}
}
func TestCompleteServiceIncidentReviewUnsupportedAndUnknown(t *testing.T) {
	for _, name := range []string{strings.Repeat("界", 100), strings.Repeat("a", 129), "wuauserv", "App Service"} {
		t.Run(name, func(t *testing.T) {
			f := newCompleteReviewFixture(t, name)
			v := f.read(t)
			if v.Observation == nil || v.Incident.ServiceName != name || v.Control.Status != "unsupported_target" || v.Control.Binding != nil || f.action.views != 0 {
				t.Fatal(v)
			}
		})
	}
	for _, mode := range []string{"missing", "stale", "future", "missing-row", "duplicate-row", "state-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompleteReviewFixture(t, "BeyondPreviewService")
			switch mode {
			case "missing":
				f.full.sampleComplete = nil
			case "stale":
				f.full.now = f.full.now.Add(301 * time.Second)
			case "future":
				f.full.sampleComplete.Source.ReceivedAt = f.full.now.Add(time.Second)
			case "missing-row":
				f.full.sampleComplete.Rows = []windowsfullservices.Row{}
			case "duplicate-row":
				f.full.sampleComplete.Rows = append(f.full.sampleComplete.Rows, f.full.sampleComplete.Rows[0])
			case "state-unavailable":
				f.full.sampleComplete.Rows[0].State = nil
				f.full.sampleComplete.Rows[0].StateQuality = "unavailable"
			}
			code, raw := f.call(t, "GET", f.path(), nil, nil)
			if mode == "future" {
				if code != 409 {
					t.Fatal("future source admitted as absence", code, string(raw))
				}
				return
			}
			var v windowsCompleteServiceIncidentReviewView
			if code != 200 || json.Unmarshal(raw, &v) != nil {
				t.Fatal(code, string(raw))
			}
			if v.Incident.Key != f.key || v.Incident.ResolvedAt != nil || v.Incident.Status != "unknown" {
				t.Fatal(v)
			}
			if mode == "state-unavailable" {
				if v.Observation == nil || v.Observation.State != "unknown" {
					t.Fatal(v)
				}
			} else if v.Observation != nil {
				t.Fatal("unknown invented an observation", v)
			}
			if mode == "missing" && v.Control.Status != "matched" {
				t.Fatal("independent ready control lost", v)
			}
		})
	}
}
func TestCompleteServiceIncidentReviewFinalLeaseAndRoutes(t *testing.T) {
	for _, mode := range []string{"source", "absence-return", "leaf", "replacement", "authority", "session", "request-wait", "rollback", "source-deadline", "broker-deadline", "final-clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompleteReviewFixture(t, "BeyondPreviewService")
			original := f.full.sampleComplete
			if mode == "absence-return" {
				f.full.sampleComplete = nil
			}
			if mode == "source-deadline" {
				f.full.now = f.full.sampleComplete.Source.CapturedAt.Add(299 * time.Second)
				f.action.record.Capabilities.CapturedAt = f.full.now.Unix()
			}
			if mode == "broker-deadline" {
				f.action.record.Capabilities.CapturedAt = f.full.now.Add(-59 * time.Second).Unix()
			}
			f.full.onIncidentGuard = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "source":
					f.full.sampleComplete.Source.ManifestSHA256 = strings.Repeat("e", 64)
				case "absence-return":
					f.full.sampleComplete = original
				case "leaf":
					f.full.currentLeaf = strings.Repeat("e", 64)
				case "replacement":
					f.full.inputs[0].CertificateHash = strings.Repeat("e", 64)
				case "authority":
					f.full.now = f.full.inputs[0].AuthorityUntil
				case "session":
					f.handler.auth.Logout(f.session.Token)
				case "request-wait":
					f.full.now = f.full.now.Add(6 * time.Second)
				case "rollback":
					f.full.now = f.full.now.Add(-time.Second)
				case "source-deadline", "broker-deadline", "final-clock":
					f.full.now = f.full.now.Add(2 * time.Second)
				}
			}
			if mode == "final-clock" {
				f.action.record.Capabilities.CapturedAt = f.full.now.Add(-59 * time.Second).Unix()
			}
			if code, raw := f.call(t, "GET", f.path(), nil, nil); code == 200 {
				t.Fatal("final boundary admitted", mode, string(raw))
			}
			if f.action.next != 0 || f.action.approvals != 0 {
				t.Fatal("boundary created action")
			}
		})
	}
	f := newCompleteReviewFixture(t, "BeyondPreviewService")
	for _, path := range []string{f.path() + "/", f.path() + "?x=1", strings.Replace(f.path(), f.key, strings.Repeat("f", 64), 1), "/api/fleet/windows-incidents/" + f.key + "/service-review"} {
		if code, _ := f.call(t, "GET", path, nil, nil); code == 200 {
			t.Fatal("route/key crossover", path)
		}
	}
	if code, _ := f.call(t, "POST", f.path(), nil, nil); code == 200 {
		t.Fatal("review write")
	}
	if code, _ := f.call(t, "GET", f.path(), nil, func(r *http.Request) { r.Header.Del("Cookie") }); code != 401 {
		t.Fatal("anonymous review", code)
	}
	if code, _ := f.call(t, "GET", f.path(), nil, func(r *http.Request) {
		r.Header.Set(windowsServiceReviewHeader, windowsaction.ServiceReviewBindingDigest(f.action.record.Binding))
	}); code != 400 {
		t.Fatal("header on review", code)
	}
}
func TestCompleteServiceIncidentReviewWireFixture(t *testing.T) {
	f := newCompleteReviewFixture(t, "BeyondPreviewService")
	views := map[string]windowsCompleteServiceIncidentReviewView{"matched": f.read(t)}
	f.full.sampleComplete = nil
	views["unknown"] = f.read(t)
	native := newCompleteReviewFixture(t, strings.Repeat("界", 100))
	views["unsupported"] = native.read(t)
	raw, e := json.MarshalIndent(views, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := "../../web/src/windows-complete-service-review-go-fixture.json"
	if os.Getenv("TRACEBOLT_WRITE_COMPLETE_SERVICE_REVIEW_FIXTURE") == "1" {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	want, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(want, raw) {
		t.Fatal("complete review fixture differs; deliberately regenerate", e)
	}
}
