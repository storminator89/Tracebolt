package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsupdatejob"
)

type updateAPIStore map[string][]byte

func (s updateAPIStore) Read(n string) ([]byte, error) {
	b, ok := s[n]
	if !ok {
		return nil, windowsupdatejob.ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (s updateAPIStore) Write(n string, b []byte) error { s[n] = bytes.Clone(b); return nil }
func (s updateAPIStore) Verify() error                  { return nil }

type updateAPIAuthority struct{ current windowsupdatejob.Current }

func (a *updateAPIAuthority) WithCurrent(_ context.Context, _ windowsupdatejob.Binding, f func(windowsupdatejob.Current) error) error {
	return f(a.current)
}

type updateAPIReadiness struct{ r windowsupdatejob.Readiness }

func (a updateAPIReadiness) Readiness(context.Context, windowsupdatejob.Binding, windowsupdatejob.Selection) (windowsupdatejob.Readiness, error) {
	return a.r, nil
}

type updateAPIFixture struct {
	handler    *operatorHandler
	session    operatorauth.Session
	authority  *updateAPIAuthority
	selection  windowsupdatejob.Selection
	device, id string
}

func newUpdateAPIFixture(t *testing.T, caps []operatorauth.Capability) updateAPIFixture {
	t.Helper()
	app := setup(t)
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: caps}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC().Unix()
	apiExecutorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	b := windowsupdatejob.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: namedDeviceID, IncarnationDigest: actionpermit.Digest([]byte("anchor")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(apiExecutorKey.Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("4", 32), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey))}
	c := windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: at + 3600}
	record, e := windowsupdatejob.NewRecordWithExecutor(c, key.Public().(ed25519.PublicKey), apiExecutorKey.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := windowsupdatejob.EncodeRecord(record)
	consent, _ := json.Marshal(c)
	s := updateAPIStore{"jobs.json": raw, "started.json": consent, "receipt.json": consent}
	a := &updateAPIAuthority{windowsupdatejob.Current{Binding: b, LeafDigest: actionpermit.Digest([]byte("current")), LeafGeneration: 1, LeafNotBefore: at - 1, LeafNotAfter: at + 300, Enabled: true}}
	selection := windowsupdatejob.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}
	r := windowsupdatejob.Readiness{Selection: selection, CapturedAt: at, Software: windowsupdatejob.Yes, Installed: windowsupdatejob.No, Hidden: windowsupdatejob.No, Downloaded: windowsupdatejob.Yes, EULAAccepted: windowsupdatejob.Yes, CanRequestUserInput: windowsupdatejob.No, CanRequireSource: windowsupdatejob.No, RequiresNetwork: windowsupdatejob.No, BundledCount: 0, InstallerBusy: windowsupdatejob.No, RebootRequiredBefore: windowsupdatejob.No, RebootBehavior: "can", OfflineVerified: windowsupdatejob.Yes}
	m, e := windowsupdatejob.Open(s, a, updateAPIReadiness{r}, key, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	app.mu.Lock()
	app.lanOnly = true
	app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: namedDeviceID, Platform: "windows"}}, nil }
	app.mu.Unlock()
	h := &operatorHandler{app: app, auth: auth, origin: "https://manager.invalid", authority: "manager.invalid", cookieName: operatorauth.CookieName, windowsUpdateJobs: m}
	return updateAPIFixture{h, session, a, selection, namedDeviceID, "update_" + strings.Repeat("6", 32)}
}

// In-process recorder only: these API fixtures never listen on a local socket.
func (f updateAPIFixture) call(t *testing.T, method, suffix string, body any, change func(*http.Request)) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://manager.invalid/api/devices/"+f.device+"/windows-update-jobs"+suffix, bytes.NewReader(raw))
	if f.handler.insecureHTTPTest {
		r.TLS = nil
	} else {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	}
	r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.session.Token})
	r.Header.Set("Origin", "https://manager.invalid")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", f.session.CSRFToken)
	if change != nil {
		change(r)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e, w.Body.String())
	}
	return w.Code, v
}
func TestWindowsUpdateJobAPIRequestReviewApprovalAndStatus(t *testing.T) {
	f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
	code, v := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": f.selection.Revision}, nil)
	if code != 200 {
		t.Fatal(code, v)
	}
	j := v["job"].(map[string]any)
	p := j["preview"].(map[string]any)
	body := map[string]any{"previewId": p["id"], "previewDigest": p["digest"], "acknowledged": false}
	if code, _ = f.call(t, "POST", "/approve", body, nil); code != 400 {
		t.Fatal("unchecked approval", code)
	}
	body["acknowledged"] = true
	for i := 0; i < 2; i++ {
		code, v = f.call(t, "POST", "/approve", body, nil)
		if code != 200 || v["job"].(map[string]any)["state"] != "approved" {
			t.Fatal(code, v)
		}
	}
	code, v = f.call(t, "GET", "", nil, nil)
	if code != 200 || v["available"] != false {
		t.Fatal(code, v)
	}
	raw, _ := json.Marshal(v)
	for _, private := range []string{"envelope\"", "signature", "publicKey"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private execution bytes exposed")
		}
	}
}
func TestWindowsUpdateJobAPINoPermissionPromotionAndHTTP(t *testing.T) {
	for _, caps := range [][]operatorauth.Capability{{operatorauth.Read}, {operatorauth.Read, operatorauth.ExecuteUpdates}, {operatorauth.Read, operatorauth.WindowsServiceControl}} {
		f := newUpdateAPIFixture(t, caps)
		if code, _ := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": 3}, nil); code != 403 {
			t.Fatal("existing capability promoted", code)
		}
	}
	f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
	f.handler.insecureHTTPTest = true
	if code, _ := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": 3}, nil); code != 409 {
		t.Fatal("plaintext mutation allowed", code)
	}
}
func TestWindowsUpdateJobAPICSRFOriginActorRevocation(t *testing.T) {
	f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
	body := map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": 3}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "bad") }} {
		if code, _ := f.call(t, "POST", "/request", body, change); code != 403 {
			t.Fatal(code)
		}
	}
	body["actorId"] = namedActorID
	if code, _ := f.call(t, "POST", "/request", body, nil); code != 400 {
		t.Fatal("request actor accepted")
	}
	delete(body, "actorId")
	f.authority.current.Revoked = true
	if code, _ := f.call(t, "POST", "/request", body, nil); code != 403 {
		t.Fatal("revoked identity allowed")
	}
	f.authority.current.Revoked = false
	f.handler.auth.Logout(f.session.Token)
	if code, _ := f.call(t, "GET", "", nil, nil); code != 401 {
		t.Fatal("revoked session read")
	}
}
func TestWindowsUpdateJobAPIDefaultOffAndNoExecutorIngress(t *testing.T) {
	f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
	f.handler.windowsUpdateJobs = nil
	code, v := f.call(t, "GET", "", nil, nil)
	if code != 200 || v["available"] != false || v["reason"] != "executor_not_configured" {
		t.Fatal(code, v)
	}
	for _, op := range []string{"claim", "result", "install", "download", "reboot"} {
		r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-update-jobs/"+op, nil)
		if _, _, ok := windowsUpdateJobRoute(r); ok {
			t.Fatal("unimplemented executor route exposed", op)
		}
	}
}

func TestWindowsUpdateJobAPIBodyReadDoesNotHoldSessionGate(t *testing.T) {
	for _, op := range []string{"request", "preview", "approve"} {
		t.Run(op, func(t *testing.T) {
			f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
			raw := `{"requestId":"` + f.id + `"}`
			if op == "request" {
				raw = `{"requestId":"` + f.id + `","updateId":"` + f.selection.UpdateID + `","revision":3}`
			}
			if op == "approve" {
				raw = `{"previewId":"` + f.id + `","previewDigest":"` + actionpermit.Digest([]byte("fixture")) + `","acknowledged":true}`
			}
			body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(raw)}
			r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-update-jobs/"+op, body)
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.session.Token})
			r.Header.Set("Origin", "https://manager.invalid")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", f.session.CSRFToken)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { f.handler.ServeHTTP(w, r); close(done) }()
			<-body.started
			logout := make(chan struct{})
			go func() { f.handler.auth.Logout(f.session.Token); close(logout) }()
			select {
			case <-logout:
			case <-time.After(5 * time.Second):
				close(body.allow)
				<-done
				t.Fatal("slow update body blocked logout")
			}
			close(body.allow)
			<-done
			if w.Code != http.StatusUnauthorized {
				t.Fatal("revoked body reached update admission", w.Code)
			}
		})
	}
}
