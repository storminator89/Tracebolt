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
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsresource"
)

// This fixture spans accepted Windows receipts -> real enrollment authority ->
// the independent background monitor -> operator.db -> authenticated GET. All
// keys/data are invented, stores are temporary and ServeHTTP opens no listener.
func TestWindowsCapacityAcceptedReceiptMonitorAndOperatorPipeline(t *testing.T) {
	testWindowsPercentageAcceptedReceiptPipeline(t, "")
}
func TestWindowsResourceAcceptedReceiptMonitorAndOperatorPipeline(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		t.Run(string(kind), func(t *testing.T) { testWindowsPercentageAcceptedReceiptPipeline(t, kind) })
	}
}
func testWindowsPercentageAcceptedReceiptPipeline(t *testing.T, kind windowsresource.Kind) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	now := time.Now().UTC().Round(0)
	base := now
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
	const password = "invented-capacity-operator-fixture"
	salt := []byte("invented-capacity-operator-salt")
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
	db, err := appstore.Open(filepath.Join(t.TempDir(), "operator.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: f.config.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: primary, EnrollmentBootstrap: bootstrap(primary), WindowsEnrollment: windows, WindowsEnrollmentBootstrap: bootstrap(windows), Devices: func() ([]model.Device, error) { return windows.Devices(ctx, now) }})
	if err != nil {
		t.Fatal(err)
	}
	id := f.identity.Approval.DeviceID
	path := "/api/devices/" + id + "/windows-capacity"
	stateRead := func() (windowscapacity.State, error) {
		if kind == "" {
			return db.WindowsCapacityState(ctx, id)
		}
		state, err := db.WindowsResourceState(ctx, id, kind)
		return state.Assessment, err
	}
	if kind != "" {
		path = "/api/devices/" + id + "/windows-resource/" + string(kind)
	}
	get := func() (int, windowscapacity.View) {
		t.Helper()
		r := httptest.NewRequest("GET", f.config.Binding.Origin+path, nil)
		r.RequestURI = path
		r.RemoteAddr = "127.0.0.1:44000"
		r.AddCookie(&http.Cookie{Name: "tracebolt-http-test-session", Value: session.Token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var v windowscapacity.View
		if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal("invalid capacity response")
		}
		if w.Code == 200 && kind != "" {
			var tagged windowsresource.View
			if json.Unmarshal(w.Body.Bytes(), &tagged) != nil || tagged.Metric != kind || tagged.SchemaVersion != windowsresource.SchemaVersion {
				t.Fatal("missing immutable resource binding")
			}
		}
		return w.Code, v
	}
	if status, v := get(); status != 200 || v.Status != "disabled" || len(v.Incidents) != 0 {
		t.Fatal("unobserved Windows identity got invented status", status, v)
	}
	value := 95.0
	makeFrame := func(seq uint64, at time.Time) []byte {
		t.Helper()
		snap, device, err := windowsmanaged.FromReport(syntheticWindowsReport(at), windowsManagerID("sample", int(seq)))
		if err != nil {
			t.Fatal(err)
		}
		metric := &device.Disk
		if kind == windowsresource.CPU {
			metric = &device.CPU
		} else if kind == windowsresource.Memory {
			metric = &device.Memory
		}
		metric.Value = &value
		metric.Quality = "healthy"
		metric.Unit = "%"
		metric.CollectedAt = at
		b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "invented-capacity-fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}
		raw := windowsManagerJSON(t, lanstore.Frame{SchemaVersion: lanstore.FrameWindowsInventoryVersion, Sequence: seq, Observation: b, WindowsInventory: &snap})
		if _, err := lanstore.ValidateFrame(raw, at); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	firstRaw := makeFrame(1, base)
	_, err = f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, firstRaw, base)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit policy POST through the real operator authentication/CSRF boundary.
	policyPath := path + "/policy"
	policyRequest := httptest.NewRequest("POST", f.config.Binding.Origin+policyPath, bytes.NewBufferString(`{"enabled":true,"thresholdPercent":90,"expectedRevision":0}`))
	policyRequest.RequestURI = policyPath
	policyRequest.RemoteAddr = "127.0.0.1:44000"
	policyRequest.AddCookie(&http.Cookie{Name: "tracebolt-http-test-session", Value: session.Token})
	policyRequest.Header.Set("Origin", f.config.Binding.Origin)
	policyRequest.Header.Set("Content-Type", "application/json")
	policyRequest.Header.Set("X-CSRF-Token", session.CSRFToken)
	policyResponse := httptest.NewRecorder()
	handler.ServeHTTP(policyResponse, policyRequest)
	if policyResponse.Code != 200 {
		t.Fatal("explicit manager policy failed", policyResponse.Code)
	}
	tick := func() {
		t.Helper()
		step, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- app.RunWindowsHealthMonitors(step, nil, nil) }()
		deadline := time.Now().Add(2 * time.Second)
		for {
			state, err := stateRead()
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			if state.EvaluatedAt != nil && state.EvaluatedAt.Equal(now) {
				contact, err := db.WindowsContactState(ctx, id)
				if err != nil || contact.EvaluatedAt == nil || !contact.EvaluatedAt.Equal(now) {
					t.Fatal("coordinated contact evaluation did not commit before capacity", err)
				}
				break
			}
			if time.Now().After(deadline) {
				cancel()
				<-done
				t.Fatal("background capacity evaluation did not commit")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	var sequence uint64 = 1
	for _, sec := range []int{0, 30, 60} {
		now = base.Add(time.Duration(sec) * time.Second)
		if sec > 0 {
			sequence++
			if _, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, makeFrame(sequence, now), now); err != nil {
				t.Fatal(err)
			}
		}
		tick()
	}
	status, v := get()
	if status != 200 || v.Status != "pressure" || len(v.Incidents) != 1 || v.Observation == nil || v.Observation.Value != 95 {
		t.Fatal("real accepted metadata failed capacity pipeline", status, v)
	}
	incident := v.Incidents[0].ID
	if kind != "" {
		disk, err := db.WindowsCapacityState(ctx, id)
		if err != nil || disk.Policy.Enabled || disk.Policy.Revision != 0 {
			t.Fatal("resource policy enabled disk", err)
		}
		other := windowsresource.CPU
		if kind == other {
			other = windowsresource.Memory
		}
		untouched, err := db.WindowsResourceState(ctx, id, other)
		if err != nil || untouched.Assessment.Policy.Enabled || untouched.Assessment.Policy.Revision != 0 {
			t.Fatal("resource policy enabled sibling", err)
		}
	}
	now = base.Add(90 * time.Second)
	duplicate, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, makeFrame(sequence, base.Add(60*time.Second)), now)
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(base.Add(60*time.Second)) {
		t.Fatal("retry refreshed capacity", err)
	}
	tick()
	if _, v = get(); v.Status != "pressure" || v.Incidents[0].ResolvedAt != nil || !v.Incidents[0].LastConfirmedAt.Equal(base.Add(60*time.Second)) {
		t.Fatal("retry renewed evidence", v)
	}
	value = 80
	for _, sec := range []int{120, 150, 180} {
		now = base.Add(time.Duration(sec) * time.Second)
		sequence++
		if _, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, makeFrame(sequence, now), now); err != nil {
			t.Fatal(err)
		}
		if _, v = get(); v.Status != "unknown" {
			t.Fatal("GET evaluated new source", v)
		}
		tick()
	}
	status, v = get()
	if status != 200 || v.Status != "within-policy" || v.Incidents[0].ID != incident || v.Incidents[0].ClosedReason != "within-policy" || v.Incidents[0].RecoveryObservation.Value != 80 {
		t.Fatal("source-spanning recovery failed", status, v)
	}
	linux, err := db.HealthStates(ctx)
	if err != nil || len(linux) != 0 {
		t.Fatal("capacity entered Linux health", err)
	}
	now = base.Add(210 * time.Second)
	control := enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", 99), ExpectedRevision: f.identity.Revision, Now: now.Unix()}
	if _, err := f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if status, _ := get(); status != 404 {
		t.Fatal("revoked capacity state readable", status)
	}
	retained, err := stateRead()
	if err != nil || len(retained.Incidents) != 1 {
		t.Fatal("revocation erased retained history", err)
	}
}
