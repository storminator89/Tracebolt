//go:build linux

package lanclient

import (
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
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
)

// This fixture spans accepted Windows receipts -> real enrollment authority ->
// the independent background monitor -> operator.db -> authenticated GET. All
// keys/data are invented, stores are temporary and ServeHTTP opens no listener.
func TestWindowsContactAcceptedReceiptMonitorAndOperatorPipeline(t *testing.T) {
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
	const password = "invented-contact-operator-fixture"
	salt := []byte("invented-contact-operator-salt")
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
	get := func() (int, windowscontact.View) {
		t.Helper()
		path := "/api/devices/" + id + "/windows-contact"
		r := httptest.NewRequest("GET", f.config.Binding.Origin+path, nil)
		r.RequestURI = path
		r.RemoteAddr = "127.0.0.1:44000"
		r.AddCookie(&http.Cookie{Name: "tracebolt-http-test-session", Value: session.Token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var v windowscontact.View
		if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal("invalid contact response")
		}
		return w.Code, v
	}
	if status, v := get(); status != 200 || v.Status != "unknown" || len(v.Incidents) != 0 {
		t.Fatal("unobserved Windows identity got invented status", status, v)
	}
	makeFrame := func(seq uint64, at time.Time) []byte {
		t.Helper()
		snap, device, err := windowsmanaged.FromReport(syntheticWindowsReport(at), windowsManagerID("sample", int(seq)))
		if err != nil {
			t.Fatal(err)
		}
		b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "invented-contact-fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}
		raw := windowsManagerJSON(t, lanstore.Frame{SchemaVersion: lanstore.FrameWindowsInventoryVersion, Sequence: seq, Observation: b, WindowsInventory: &snap})
		if _, err := lanstore.ValidateFrame(raw, at); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	firstRaw := makeFrame(1, base)
	first, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, firstRaw, base)
	if err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		step, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- app.RunWindowsContactMonitor(step, nil) }()
		deadline := time.Now().Add(2 * time.Second)
		for {
			state, err := db.WindowsContactState(ctx, id)
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			if state.EvaluatedAt != nil && state.EvaluatedAt.Equal(now) {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				<-done
				t.Fatal("background contact evaluation did not commit")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for sec := 0; sec <= 210; sec += 30 {
		now = base.Add(time.Duration(sec) * time.Second)
		tick()
	}
	status, v := get()
	if status != 200 || v.Status != "overdue" || len(v.Incidents) != 1 || !v.LastAcceptedAt.Equal(first.ReceivedAt) {
		t.Fatal("accepted source did not become durable overdue report", status, v)
	}
	incident := v.Incidents[0].ID
	now = base.Add(240 * time.Second)
	duplicate, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, firstRaw, now)
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("retry refreshed contact", err)
	}
	tick()
	if _, v = get(); v.Status != "overdue" || v.Incidents[0].ResolvedAt != nil {
		t.Fatal("duplicate recovered incident")
	}
	now = base.Add(270 * time.Second)
	if _, err := f.store.SaveObservation(ctx, f.identity.InvitationID, f.identity.Issuance.CertificateHash, makeFrame(2, now), now); err != nil {
		t.Fatal(err)
	}
	if _, v = get(); v.Status != "unknown" || v.Sequence != 2 || v.Incidents[0].ResolvedAt != nil {
		t.Fatal("GET evaluated newly accepted recovery")
	}
	for sec := 270; sec <= 330; sec += 30 {
		now = base.Add(time.Duration(sec) * time.Second)
		tick()
	}
	status, v = get()
	if status != 200 || v.Status != "recent" || len(v.Incidents) != 1 || v.Incidents[0].ID != incident || v.Incidents[0].ResolvedAt == nil {
		t.Fatal("confirmed receipt recovery missing", status, v)
	}
	linux, err := db.HealthStates(ctx)
	if err != nil || len(linux) != 0 {
		t.Fatal("Windows monitor entered Linux health", err)
	}
	now = base.Add(360 * time.Second)
	control := enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", 99), ExpectedRevision: f.identity.Revision, Now: now.Unix()}
	if _, err := f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if status, _ := get(); status != 404 {
		t.Fatal("revoked Windows history readable", status)
	}
	retained, err := db.WindowsContactState(ctx, id)
	if err != nil || len(retained.Incidents) != 1 {
		t.Fatal("revocation erased private history", err)
	}
}
