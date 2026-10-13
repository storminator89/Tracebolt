package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
)

type serviceReviewAuthorityFixture struct {
	*fixtureWindowsCapacitySource
	insideLease bool
	beforeLease func()
	beforeGuard func()
}

func (s *serviceReviewAuthorityFixture) WithWindowsIncidentAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	if s.beforeLease != nil {
		s.beforeLease()
	}
	s.insideLease = true
	defer func() { s.insideLease = false }()
	return s.fixtureWindowsCapacitySource.WithWindowsIncidentAuthority(ctx, in, func(guard func(time.Time) error) error {
		return fn(func(at time.Time) error {
			if s.beforeGuard != nil {
				s.beforeGuard()
			}
			return guard(at)
		})
	})
}

type serviceReviewActionFixture struct {
	windowsActionAPIFixture
	source                                 *serviceReviewAuthorityFixture
	views, expectedViews, expectedPreviews int
	unavailable                            bool
	onView                                 func()
}

func (f *serviceReviewActionFixture) Available() bool { return !f.unavailable }
func (f *serviceReviewActionFixture) ViewAt(context.Context, string) (windowsactionjob.Record, time.Time, error) {
	if f.source.insideLease {
		panic("enrollment action view entered from source authority lease")
	}
	f.views++
	if f.onView != nil {
		f.onView()
	}
	f.at = f.source.now
	return f.record, f.at, nil
}
func (f *serviceReviewActionFixture) ViewExpectedAt(ctx context.Context, device, expected string) (windowsactionjob.Record, time.Time, error) {
	f.expectedViews++
	if windowsaction.ServiceReviewBindingDigest(f.record.Binding) != expected {
		return windowsactionjob.Record{}, f.at, windowsactionjob.ErrConflict
	}
	return f.ViewAt(ctx, device)
}
func (f *serviceReviewActionFixture) PreviewExpected(ctx context.Context, device, actor, target, operation, expected string) (windowsactionjob.Record, error) {
	f.expectedPreviews++
	if windowsaction.ServiceReviewBindingDigest(f.record.Binding) != expected {
		return windowsactionjob.Record{}, windowsactionjob.ErrConflict
	}
	return f.Preview(ctx, device, actor, target, operation)
}

type serviceReviewAPIFixture struct {
	handler     *operatorHandler
	session     operatorauth.Session
	source      *serviceReviewAuthorityFixture
	actions     *serviceReviewActionFixture
	key, device string
}

func newServiceReviewAPIFixture(t *testing.T, capability bool) serviceReviewAPIFixture {
	t.Helper()
	app := setup(t)
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(at)
	in.Services = windowsservicehealth.Sample{CollectedAt: at, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsmanaged.Service{{Name: "FixtureService", DisplayName: "Fixture service", State: "stopped"}}}}
	source := &serviceReviewAuthorityFixture{fixtureWindowsCapacitySource: &fixtureWindowsCapacitySource{now: at, inputs: []windowscapacity.Input{in}}}
	monitor, err := newWindowsCapacityMonitor(app.store, source)
	if err != nil {
		t.Fatal(err)
	}
	app.windowsCapacity = monitor
	if _, err = app.store.ConfigureWindowsService(context.Background(), windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, true, []string{"FixtureService"}, 0, at); err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= 4; n++ {
		if n > 0 {
			advanceCapacity(source.fixtureWindowsCapacitySource, 30, 95)
			source.inputs[0].Services.CollectedAt = source.now
		}
		if err = monitor.evaluate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := app.store.WindowsIncidentSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key := ""
	for k, target := range snapshot.Targets() {
		if target.Domain == "service" {
			key = k
		}
	}
	if key == "" {
		t.Fatal("no service incident")
	}
	caps := []operatorauth.Capability{operatorauth.Read}
	if capability {
		caps = append(caps, operatorauth.WindowsServiceControl)
	}
	auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: caps}}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	binding := windowsaction.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), EndpointID: in.DeviceID, KeyID: windowsaction.Digest(private.Public().(ed25519.PublicKey)), IncarnationDigest: "sha256:" + in.CertificateHash, InstallationID: "broker_" + strings.Repeat("2", 32), GrantDigest: windowsaction.Digest([]byte("grant")), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("config"))}
	record, err := windowsactionjob.New(binding, private.Public().(ed25519.PublicKey), source.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = record.Report(windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: binding, CapturedAt: source.now.Unix(), Enabled: true}, source.now); err != nil {
		t.Fatal(err)
	}
	actions := &serviceReviewActionFixture{windowsActionAPIFixture: windowsActionAPIFixture{record: record, at: source.now, key: private}, source: source}
	app.mu.Lock()
	app.lanOnly = true
	app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: in.DeviceID, Platform: "windows"}}, nil }
	app.mu.Unlock()
	handler := &operatorHandler{app: app, auth: auth, origin: "https://manager.invalid", authority: "manager.invalid", cookieName: operatorauth.CookieName, windowsActions: actions}
	return serviceReviewAPIFixture{handler, session, source, actions, key, in.DeviceID}
}
func (f serviceReviewAPIFixture) path() string { return inboxPath + "/" + f.key + "/service-review" }
func (f serviceReviewAPIFixture) actionPath() string {
	return "/api/devices/" + f.device + "/windows-service-actions"
}

// In-process requests only: no listener, native service, provider, or host grant.
func (f serviceReviewAPIFixture) call(t *testing.T, method, path string, body any, change func(*http.Request)) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, "https://manager.invalid"+path, bytes.NewReader(raw))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.session.Token})
	request.Header.Set("Origin", "https://manager.invalid")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", f.session.CSRFToken)
	if change != nil {
		change(request)
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response.Code, response.Body.Bytes()
}
func (f serviceReviewAPIFixture) read(t *testing.T) windowsServiceIncidentReviewView {
	t.Helper()
	code, raw := f.call(t, "GET", f.path(), nil, nil)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	var view windowsServiceIncidentReviewView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func TestWindowsServiceIncidentReviewExactProjectionDoesNotCreateWork(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	before, err := f.handler.app.store.WindowsIncidentSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := f.read(t)
	if first.Control.Status != "matched" || first.Control.Binding == nil || first.Control.BindingDigest == nil || *first.Control.BindingDigest != windowsaction.ServiceReviewBindingDigest(f.actions.record.Binding) || first.Observation == nil || first.Observation.Name != "FixtureService" || first.Observation.State != "stopped" {
		t.Fatal(first)
	}
	if first.Incident.Key != f.key || first.Incident.Domain != "service" || first.Incident.ResolvedAt != nil {
		t.Fatal("retained episode changed")
	}
	f.read(t)
	after, err := f.handler.app.store.WindowsIncidentSnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("review changed incident or policy", err)
	}
	if f.actions.next != 0 || f.actions.approvals != 0 || f.actions.record.Preview != nil || len(f.actions.record.Jobs) != 0 {
		t.Fatal("projection created work")
	}
	// Renewal changes current authority expiry, never the original identity anchor.
	f.source.inputs[0].AuthorityUntil = f.source.inputs[0].AuthorityUntil.Add(time.Hour)
	renewed := f.read(t)
	if renewed.Control.Status != "matched" || *renewed.Control.BindingDigest != *first.Control.BindingDigest || !reflect.DeepEqual(renewed.Incident, first.Incident) {
		t.Fatal("renewal replaced original episode")
	}
	raw, _ := json.Marshal(first)
	for _, private := range []string{"invitationId", "certificateHash", "publicKey", "envelope", "sequenceFloor"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private state exposed", private)
		}
	}
}

func TestWindowsServiceIncidentReviewBlockedControls(t *testing.T) {
	for _, test := range []struct {
		name, status string
		capability   bool
		change       func(*serviceReviewAPIFixture)
	}{
		{"missing capability", "operator_capability_required", false, func(*serviceReviewAPIFixture) {}},
		{"missing manager", "not_configured", true, func(f *serviceReviewAPIFixture) { f.handler.windowsActions = nil }},
		{"unavailable manager", "unavailable", true, func(f *serviceReviewAPIFixture) { f.actions.unavailable = true }},
		{"missing broker grant", "unavailable", true, func(f *serviceReviewAPIFixture) { f.actions.record.Capabilities = nil }},
		{"busy broker", "unavailable", true, func(f *serviceReviewAPIFixture) { f.actions.record.Capabilities.Busy = true }},
		{"case mismatch", "target_mismatch", true, func(f *serviceReviewAPIFixture) { f.actions.record.Binding.Target = "fixtureservice" }},
		{"replacement incarnation", "target_mismatch", true, func(f *serviceReviewAPIFixture) {
			f.actions.record.Binding.IncarnationDigest = windowsaction.Digest([]byte("replacement"))
		}},
		{"other endpoint", "target_mismatch", true, func(f *serviceReviewAPIFixture) {
			f.actions.record.Binding.EndpointID = "agent_" + strings.Repeat("d", 32)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newServiceReviewAPIFixture(t, test.capability)
			test.change(&f)
			v := f.read(t)
			if v.Control.Status != test.status || v.Control.Binding != nil || v.Control.BindingDigest != nil {
				t.Fatal(v.Control)
			}
			if f.actions.next != 0 || f.actions.approvals != 0 {
				t.Fatal("blocked review created work")
			}
		})
	}
}

func TestWindowsServiceIncidentReviewObservationNeverInventsStopped(t *testing.T) {
	for _, change := range []string{"missing", "duplicate", "case", "stale", "future", "denied", "partial", "pending"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceReviewAPIFixture(t, true)
			s := &f.source.inputs[0].Services
			switch change {
			case "missing":
				s.Services.Rows = []windowsmanaged.Service{}
				s.Services.ObservedCount = 0
			case "duplicate":
				s.Services.Rows = append(s.Services.Rows, s.Services.Rows[0])
				s.Services.ObservedCount = 2
			case "case":
				s.Services.Rows[0].Name = "fixtureservice"
			case "stale":
				s.CollectedAt = f.source.now.Add(-121 * time.Second)
			case "future":
				s.CollectedAt = f.source.now.Add(time.Second)
			case "denied":
				s.Services.Quality = "denied"
			case "partial":
				s.Services.Quality = "partial"
				s.Services.Complete = false
				s.Services.Truncated = true
				s.Services.ObservedCount = 2
			case "pending":
				s.Services.Rows[0].State = "start_pending"
			}
			v := f.read(t)
			if change == "partial" {
				if v.Observation == nil || v.Observation.Quality != "partial" || !v.Observation.Truncated || v.Observation.Complete {
					t.Fatal(v.Observation)
				}
			} else if change == "pending" {
				if v.Observation == nil || v.Observation.State != "start_pending" {
					t.Fatal(v.Observation)
				}
			} else if v.Observation != nil {
				t.Fatal("unqualified row became observation", v.Observation)
			}
			if v.Incident.ResolvedAt != nil {
				t.Fatal("unknown observation resolved history")
			}
		})
	}
}

func TestWindowsServiceIncidentReviewRejectsObsoleteAndFinalAuthority(t *testing.T) {
	for _, change := range []string{"replacement before", "replacement after action read", "invitation", "revoked", "expired", "final expiry", "final source guard", "final broker expiry", "final observation expiry", "session", "clock"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceReviewAPIFixture(t, true)
			switch change {
			case "replacement before":
				f.source.inputs[0].CertificateHash = strings.Repeat("e", 64)
			case "replacement after action read":
				f.actions.onView = func() { f.source.inputs[0].CertificateHash = strings.Repeat("e", 64) }
			case "invitation":
				f.source.inputs[0].InvitationID = "invite_" + strings.Repeat("e", 32)
			case "revoked":
				f.source.inputs[0].Authorized = false
			case "expired":
				f.source.inputs[0].AuthorityUntil = f.source.now
			case "final expiry":
				f.source.beforeLease = func() { f.source.now = f.source.inputs[0].AuthorityUntil }
			case "final source guard":
				f.source.beforeGuard = func() { f.source.inputs[0].Authorized = false }
			case "final broker expiry":
				f.actions.record.Capabilities.CapturedAt = f.source.now.Add(-59 * time.Second).Unix()
				f.source.beforeGuard = func() { f.source.now = f.source.now.Add(2 * time.Second) }
			case "final observation expiry":
				f.source.inputs[0].Services.CollectedAt = f.source.now.Add(-119 * time.Second)
				f.source.beforeGuard = func() { f.source.now = f.source.now.Add(2 * time.Second) }
			case "session":
				f.source.beforeLease = func() { f.handler.auth.Logout(f.session.Token) }
			case "clock":
				f.source.beforeLease = func() { f.source.now = f.source.now.Add(-time.Second) }
			}
			code, raw := f.call(t, "GET", f.path(), nil, nil)
			if code == 200 || bytes.Contains(raw, []byte(`"incident"`)) {
				t.Fatal("obsolete private projection released", code, string(raw))
			}
		})
	}
}

func TestWindowsServiceReviewHeaderPinsManualPreviewAndKeepsV1(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	review := f.read(t)
	digest := *review.Control.BindingDigest
	header := func(r *http.Request) { r.Header.Set(windowsServiceReviewHeader, digest) }
	code, raw := f.call(t, "GET", f.actionPath(), nil, header)
	if code != 200 || f.actions.expectedViews != 1 {
		t.Fatal(code, string(raw))
	}
	body := map[string]string{"target": "FixtureService", "operation": "restart"}
	code, raw = f.call(t, "POST", f.actionPath()+"/preview", body, header)
	if code != 200 || f.actions.expectedPreviews != 1 || f.actions.next != 1 || f.actions.approvals != 0 {
		t.Fatal(code, string(raw))
	}
	var preview windowsServiceActionView
	if json.Unmarshal(raw, &preview) != nil || preview.Preview == nil || preview.SchemaVersion != "tracebolt.windows-service-action-view.v1" {
		t.Fatal(string(raw))
	}
	// Replacing any immutable grant detail between the review and a manual click
	// cannot fall back to current device-ID authority or create a new preview.
	f.actions.record.Binding.GrantDigest = windowsaction.Digest([]byte("replacement grant"))
	f.actions.record.Preview = nil
	for _, method := range []string{"GET", "POST"} {
		path := f.actionPath()
		var payload any
		if method == "POST" {
			path += "/preview"
			payload = body
		}
		code, raw = f.call(t, method, path, payload, header)
		if code != 409 || f.actions.record.Preview != nil || f.actions.next != 1 {
			t.Fatal("replacement accepted", code, string(raw))
		}
	}
	// Ordinary v1 has no new body fields or forced incident selection.
	f.actions.record.Capabilities.Binding = f.actions.record.Binding
	code, raw = f.call(t, "POST", f.actionPath()+"/preview", body, nil)
	if code != 200 || f.actions.next != 2 {
		t.Fatal("ordinary v1 changed", code, string(raw))
	}
}

func TestWindowsServiceReviewHeaderAndRouteStrictness(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	digest := windowsaction.ServiceReviewBindingDigest(f.actions.record.Binding)
	for _, test := range []struct {
		method, path string
		values       []string
	}{
		{"GET", f.actionPath(), []string{digest, digest}}, {"GET", f.actionPath(), []string{""}}, {"GET", f.actionPath(), []string{strings.ToUpper(digest)}}, {"GET", f.actionPath(), []string{digest + ", " + digest}},
		{"POST", f.actionPath() + "/approve", []string{digest}}, {"GET", f.actionPath() + "/history", []string{digest}}, {"GET", f.path(), []string{digest}}, {"GET", "/api/devices", []string{digest}},
	} {
		code, raw := f.call(t, test.method, test.path, nil, func(r *http.Request) { r.Header[http.CanonicalHeaderKey(windowsServiceReviewHeader)] = test.values })
		if code != 400 {
			t.Fatal(test, code, string(raw))
		}
	}
	for _, path := range []string{f.path() + "/", f.path() + "?ignored=1", strings.Replace(f.path(), f.key, strings.ToUpper(f.key), 1), strings.Replace(f.path(), f.key, "%61"+f.key[1:], 1)} {
		if code, _ := f.call(t, "GET", path, nil, nil); code == 200 {
			t.Fatal("noncanonical route", path)
		}
	}
	if code, _ := f.call(t, "POST", f.path(), nil, nil); code != 403 {
		t.Fatal("review mutation route", code)
	}
	if code, _ := f.call(t, "GET", f.path(), nil, func(r *http.Request) { r.Header.Del("Cookie") }); code != 401 {
		t.Fatal("anonymous review", code)
	}
	if f.actions.next != 0 || f.actions.approvals != 0 {
		t.Fatal("invalid header caused work")
	}
}

var updateWindowsServiceReviewFixture = flag.Bool("update-windows-service-review-fixture", false, "regenerate reviewed Windows service-incident review Go/TypeScript fixture")

func TestWindowsServiceIncidentReviewWireFixture(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	views := map[string]windowsServiceIncidentReviewView{"matched": f.read(t)}
	f.actions.record.Capabilities = nil
	views["unavailable"] = f.read(t)
	f.source.inputs[0].Services.Services.Rows = []windowsmanaged.Service{}
	f.source.inputs[0].Services.Services.ObservedCount = 0
	f.handler.windowsActions = nil
	views["missingObservation"] = f.read(t)
	raw, err := json.MarshalIndent(views, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-service-incident-review.json")
	if *updateWindowsServiceReviewFixture {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, raw) {
		t.Fatal("Windows service review fixture changed; review before regeneration")
	}
}

func TestWindowsServiceReviewExpectedMethodsNeverFallBack(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	digest := windowsaction.ServiceReviewBindingDigest(f.actions.record.Binding)
	// An older adapter that exposes ordinary v1 must never silently downgrade a pin.
	f.handler.windowsActions = &f.actions.windowsActionAPIFixture
	if view := f.read(t); view.Control.Status != "unavailable" || view.Control.Binding != nil {
		t.Fatal("old adapter advertised a pinned control", view.Control)
	}
	for _, method := range []string{"GET", "POST"} {
		path := f.actionPath()
		var body any
		if method == "POST" {
			path += "/preview"
			body = map[string]string{"target": "FixtureService", "operation": "restart"}
		}
		code, raw := f.call(t, method, path, body, func(r *http.Request) { r.Header.Set(windowsServiceReviewHeader, digest) })
		if code != 409 || f.actions.next != 0 || f.actions.record.Preview != nil {
			t.Fatal("pinned request downgraded", code, string(raw))
		}
	}
	if code, _ := f.call(t, "GET", f.actionPath(), nil, nil); code != 200 {
		t.Fatal("ordinary v1 adapter changed", code)
	}
}

func TestWindowsServiceIncidentReviewSharedAdminCannotControl(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash()})
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	f.handler.auth = auth
	view := f.read(t)
	if view.Control.Status != "operator_capability_required" || view.Control.Binding != nil || f.actions.views != 0 {
		t.Fatal("shared admin gained service control", view.Control)
	}
	if code, _ := f.call(t, "POST", f.path(), nil, nil); code != 405 {
		t.Fatal("review exposed mutation", code)
	}
}

func TestWindowsServiceIncidentReviewClosedEpisodeKeepsLifecycle(t *testing.T) {
	f := newServiceReviewAPIFixture(t, true)
	before := f.read(t)
	input := f.source.inputs[0]
	state, err := f.handler.app.store.WindowsServiceState(context.Background(), input.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.handler.app.store.ConfigureWindowsService(context.Background(), windowsservicehealth.Input{Input: input.Input, Sample: input.Services}, false, state.Policy.Services, state.Policy.Revision, f.source.now); err != nil {
		t.Fatal(err)
	}
	after := f.read(t)
	if after.Incident.Key != before.Incident.Key || after.Incident.ResolvedAt == nil || after.Incident.ClosedReason != "policy-changed" || after.Incident.RecoveryCollectedAt != nil || !after.Incident.OpenedAt.Equal(before.Incident.OpenedAt) || !after.Incident.CollectedAt.Equal(*before.Incident.CollectedAt) {
		t.Fatal("closure or original evidence changed", after.Incident)
	}
	if f.actions.next != 0 || f.actions.approvals != 0 {
		t.Fatal("closed incident created action")
	}
}

func TestWindowsServiceReviewUnpinnedV1ApprovalStillExact(t *testing.T) {
	for _, operation := range []string{windowsaction.Start, windowsaction.Stop, windowsaction.Restart} {
		t.Run(operation, func(t *testing.T) {
			f := newServiceReviewAPIFixture(t, true)
			code, raw := f.call(t, "POST", f.actionPath()+"/preview", map[string]string{"target": "FixtureService", "operation": operation}, nil)
			var view windowsServiceActionView
			if code != 200 || json.Unmarshal(raw, &view) != nil || view.Preview == nil {
				t.Fatal(code, string(raw))
			}
			if code, _ = f.call(t, "POST", f.actionPath()+"/approve", map[string]string{"previewId": view.Preview.ID, "previewDigest": windowsaction.ServiceReviewBindingDigest(view.Preview.Binding)}, nil); code != 409 || f.actions.approvals != 0 {
				t.Fatal("review pin substituted for preview approval", code)
			}
			body := map[string]string{"previewId": view.Preview.ID, "previewDigest": view.Preview.Digest}
			for n := 0; n < 2; n++ {
				code, raw = f.call(t, "POST", f.actionPath()+"/approve", body, nil)
				if code != 200 {
					t.Fatal(code, string(raw))
				}
			}
			if f.actions.approvals != 1 || len(f.actions.record.Jobs) != 1 || f.actions.record.Jobs[0].Preview.Operation != operation {
				t.Fatal("ordinary v1 approval changed")
			}
		})
	}
}
