//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	appstore "localrmm/internal/store"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
)

// This exercises accepted Windows frames, the real enrollment source, the
// production coordinated monitor, durable operator state and the authenticated
// API. It performs no host reads, service actions or network-listener operations.
func TestWindowsServiceAcceptedReceiptMonitorAndOperatorPipeline(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	base := time.Now().UTC().Round(0)
	now := base
	primaryConfig := f.config
	primaryConfig.Binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	primaryStore, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "primary", "enrollment.sqlite"), primaryConfig, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer primaryStore.Close()
	primary, err := enrollmentservice.New(primaryStore, f.issuer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	windows, err := enrollmentservice.New(f.store, f.issuer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	bootstrap := func(s *enrollmentservice.Service) api.EnrollmentBootstrap {
		b := s.Binding()
		return api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: b.InstanceID, Profile: b.Profile, EnrollmentOrigin: b.Origin, AgentOrigin: b.Origin, CollectionProfile: b.CollectionProfile, IssuerRootPEM: publicPEM(f.issuer.RootDER()), IssuerPEM: publicPEM(f.issuer.IssuerDER())}
	}
	registry, err := lantrust.NewRegistry(ctx, []byte(publicPEM(f.issuer.IssuerDER())), lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	const password = "invented-service-operator-fixture"
	salt := []byte("invented-service-operator-salt")
	derived := argon2.IDKey([]byte(password), salt, 2, 65536, 1, 32)
	hash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(ctx, "127.0.0.1", password)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Logout(session.Token)
	dbPath := filepath.Join(t.TempDir(), "operator.sqlite")
	db, err := appstore.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	var app *api.Server
	var handler http.Handler
	openHandler := func() {
		t.Helper()
		app, err = api.New(db, 8787, t.TempDir(), model.Device{})
		if err != nil {
			t.Fatal(err)
		}
		handler, err = api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: f.config.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: primary, EnrollmentBootstrap: bootstrap(primary), WindowsEnrollment: windows, WindowsEnrollmentBootstrap: bootstrap(windows), Devices: func() ([]model.Device, error) { return windows.Devices(ctx, now) }})
		if err != nil {
			t.Fatal(err)
		}
	}
	openHandler()
	id := f.identity.Approval.DeviceID
	path := "/api/devices/" + id + "/windows-services"
	request := func(method, target, body string, authenticated, csrf bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, f.config.Binding.Origin+target, bytes.NewBufferString(body))
		r.RequestURI = target
		r.RemoteAddr = "127.0.0.1:44000"
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "tracebolt-http-test-session", Value: session.Token})
		}
		if method == http.MethodPost {
			r.Header.Set("Origin", f.config.Binding.Origin)
			r.Header.Set("Content-Type", "application/json")
			if csrf {
				r.Header.Set("X-CSRF-Token", session.CSRFToken)
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	get := func() windowsservicehealth.View {
		t.Helper()
		w := request(http.MethodGet, path, "", true, false)
		var v windowsservicehealth.View
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.SchemaVersion != windowsservicehealth.SchemaVersion || v.DeviceID != id {
			t.Fatalf("invalid service view: status=%d body=%s", w.Code, w.Body.String())
		}
		return v
	}
	if w := request(http.MethodGet, path, "", false, false); w.Code != http.StatusUnauthorized {
		t.Fatal("service metadata bypassed authentication", w.Code)
	}
	if v := get(); v.Status != "disabled" || v.Policy.Enabled || v.Policy.Revision != 0 || len(v.Policy.Services) != 0 || len(v.Incidents) != 0 || v.Inventory != nil {
		t.Fatal("unobserved identity invented service policy or metadata", v)
	}
	const policy = `{"enabled":true,"services":["Spooler"],"expectedRevision":0}`
	if w := request(http.MethodPost, path+"/policy", policy, true, true); w.Code != http.StatusConflict {
		t.Fatal("unobserved service name became selectable", w.Code)
	}
	var sequence uint64
	var latestRaw []byte
	var latestReceipt time.Time
	accept := func(receivedSec, capturedSec int, rows ...windowsinventory.Service) {
		t.Helper()
		now = base.Add(time.Duration(receivedSec) * time.Second)
		captured := base.Add(time.Duration(capturedSec) * time.Second)
		sequence++
		report := syntheticWindowsReport(captured)
		// Positive unique rows remain usable despite explicitly partial visibility.
		report.Services = windowsinventory.Section[windowsinventory.Service]{Source: "Invented caller-visible SCM fixture", Scope: "Invented partial service scope", Quality: "limited", Rows: rows}
		snapshot, device, err := windowsmanaged.FromReport(report, windowsManagerID("sample", int(sequence)))
		if err != nil {
			t.Fatal(err)
		}
		b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "invented-service-fixture", GeneratedAt: captured, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}
		latestRaw = windowsManagerJSON(t, lanstore.Frame{SchemaVersion: lanstore.FrameWindowsInventoryVersion, Sequence: sequence, Observation: b, WindowsInventory: &snapshot})
		if _, err = lanstore.ValidateFrame(latestRaw, now); err != nil {
			t.Fatal(err)
		}
		receipt, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, latestRaw, now)
		if err != nil || receipt.Duplicate {
			t.Fatal("new service frame was not accepted", err)
		}
		latestReceipt = receipt.ReceivedAt
	}
	row := func(name, state string) windowsinventory.Service {
		return windowsinventory.Service{Name: name, DisplayName: "Invented " + name, State: state}
	}
	accept(0, 0, row("Spooler", "stopped"), row("Other", "running"))
	if v := get(); v.Status != "disabled" || v.Inventory == nil || v.Inventory.Quality != "partial" || v.Inventory.Complete || v.Inventory.CountExact || len(v.Inventory.Services) != 2 {
		t.Fatal("accepted partial rows enabled policy or lost their visibility boundary", v)
	}
	if w := request(http.MethodPost, path+"/policy", policy, true, false); w.Code != http.StatusForbidden {
		t.Fatal("policy bypassed CSRF", w.Code)
	}
	if w := request(http.MethodPost, path+"/policy", policy, true, true); w.Code != http.StatusOK {
		t.Fatalf("explicit policy failed: %d %s", w.Code, w.Body.String())
	}
	if v := get(); v.Status != "unknown" || !v.Policy.Enabled || v.Policy.Revision != 1 || v.EvaluatedAt != nil || len(v.Incidents) != 0 {
		t.Fatal("policy save evaluated or confirmed source", v)
	}
	if w := request(http.MethodPost, path+"/policy", policy, true, true); w.Code != http.StatusConflict {
		t.Fatal("stale policy revision accepted", w.Code)
	}
	tick := func() {
		t.Helper()
		step, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- app.RunWindowsHealthMonitors(step, nil, nil) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		deadline := time.Now().Add(3 * time.Second)
		for {
			state, err := db.WindowsServiceState(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if state.EvaluatedAt != nil && state.EvaluatedAt.Equal(now) {
				contact, err := db.WindowsContactState(ctx, id)
				if err != nil || contact.EvaluatedAt == nil || !contact.EvaluatedAt.Equal(now) {
					t.Fatal("production contact monitor did not commit before service monitor", err)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("production service monitor did not commit")
			}
			time.Sleep(time.Millisecond)
		}
	}
	for _, sec := range []int{0, 30, 60, 90, 120} {
		now = base.Add(time.Duration(sec) * time.Second)
		if sec == 90 {
			retry, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, latestRaw, now)
			if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(latestReceipt) {
				t.Fatal("retry renewed original receipt", err)
			}
		}
		tick()
		if v := get(); v.Status != "pending" || len(v.Incidents) != 0 || len(v.Checks) != 1 || v.Checks[0].Observation.Sequence != 1 {
			t.Fatal("repeated sample confirmed service incident", sec, v)
		}
	}
	accept(130, 125, row("Spooler", "stopped"))
	if v := get(); v.Status != "unknown" || len(v.Incidents) != 0 {
		t.Fatal("GET evaluated new accepted tuple", v)
	}
	tick()
	v := get()
	if v.Status != "attention" || len(v.Incidents) != 1 || v.Incidents[0].Name != "Spooler" || !v.Incidents[0].OpeningObservation.CollectedAt.Equal(base.Add(125*time.Second)) || !v.Incidents[0].OpeningObservation.ReceivedAt.Equal(base.Add(130*time.Second)) || !v.Incidents[0].OpenedAt.Equal(now) {
		t.Fatal("advancing accepted source failed service pipeline or changed capture time", v)
	}
	incident := v.Incidents[0].ID
	for _, step := range []struct {
		at   int
		rows []windowsinventory.Service
	}{
		{160, []windowsinventory.Service{row("Other", "running")}},
		{190, []windowsinventory.Service{row("Spooler", "running"), row("Spooler", "stopped")}},
		{220, []windowsinventory.Service{row("Spooler", "start_pending")}},
		{250, []windowsinventory.Service{row("spooler", "running")}},
	} {
		accept(step.at, step.at-5, step.rows...)
		tick()
		v = get()
		if v.Status != "unknown" || len(v.Checks) != 1 || v.Checks[0].Observation != nil || len(v.Incidents) != 1 || v.Incidents[0].ID != incident || v.Incidents[0].ResolvedAt != nil || !v.Incidents[0].LastConfirmedAt.Equal(base.Add(130*time.Second)) {
			t.Fatal("missing, duplicate, pending or case-different row recovered an incident", step.at, v)
		}
	}
	accept(280, 275, row("Spooler", "paused"))
	tick()
	if v = get(); v.Status != "attention" || v.Incidents[0].ID != incident || v.Incidents[0].LastBadObservation.State != "paused" {
		t.Fatal("explicit paused evidence lost existing incident", v)
	}
	accept(310, 305, row("Spooler", "running"))
	tick()
	for _, sec := range []int{340, 370} {
		now = base.Add(time.Duration(sec) * time.Second)
		tick()
		if v = get(); v.Status != "attention" || v.Incidents[0].ResolvedAt != nil {
			t.Fatal("one running sample recovered the incident", v)
		}
	}
	accept(400, 395, row("Spooler", "running"))
	tick()
	if v = get(); v.Status != "running" || v.Incidents[0].ID != incident || v.Incidents[0].ClosedReason != "running" || v.Incidents[0].RecoveryObservation == nil || !v.Incidents[0].RecoveryObservation.CollectedAt.Equal(base.Add(395*time.Second)) {
		t.Fatal("source-spanning recovery failed", v)
	}
	before, err := db.WindowsServiceState(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	encodedBefore, err := windowsservicehealth.Encode(before)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = appstore.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	openHandler()
	after, err := db.WindowsServiceState(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	encodedAfter, err := windowsservicehealth.Encode(after)
	if err != nil || !bytes.Equal(encodedBefore, encodedAfter) {
		t.Fatal("reopen changed durable service policy, floors or history", err)
	}
	if v = get(); v.Status != "unknown" || len(v.Incidents) != 1 || v.Incidents[0].ID != incident || v.Incidents[0].ClosedReason != "running" {
		t.Fatal("restarted manager invented current confidence or lost history", v)
	}
	for _, sec := range []int{430, 460, 490, 520, 550} {
		accept(sec, sec-5, row("Spooler", "stopped"))
		tick()
	}
	if v = get(); v.Status != "attention" || len(v.Incidents) != 2 || v.Incidents[0].ID == incident || v.Incidents[0].ResolvedAt != nil || v.Incidents[1].ID != incident {
		t.Fatal("durable next incident identity did not survive reopening", v)
	}
	disk, err := db.WindowsCapacityState(ctx, id)
	if err != nil || disk.Policy.Enabled || disk.Policy.Revision != 0 {
		t.Fatal("service policy altered capacity sibling", err)
	}
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		state, err := db.WindowsResourceState(ctx, id, kind)
		if err != nil || state.Assessment.Policy.Enabled || state.Assessment.Policy.Revision != 0 {
			t.Fatal("service policy altered resource sibling", kind, err)
		}
	}
	linux, err := db.HealthStates(ctx)
	if err != nil || len(linux) != 0 {
		t.Fatal("service policy entered Linux health", err)
	}
	now = base.Add(580 * time.Second)
	control := enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", 99), ExpectedRevision: f.identity.Revision, Now: now.Unix()}
	if _, err = f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, path, "", true, false); w.Code != http.StatusNotFound {
		t.Fatal("revoked service metadata remained readable", w.Code)
	}
	retained, err := db.WindowsServiceState(ctx, id)
	if err != nil || len(retained.Incidents) != 2 || retained.Incidents[0].ResolvedAt != nil {
		t.Fatal("authority loss erased or recovered retained service history", err)
	}
}
