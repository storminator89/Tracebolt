package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowssoftwarejob"
)

type softwareAPIStore map[string][]byte

func (s softwareAPIStore) Read(n string) ([]byte, error) {
	b, ok := s[n]
	if !ok {
		return nil, windowssoftwarejob.ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (s softwareAPIStore) Write(n string, b []byte) error { s[n] = bytes.Clone(b); return nil }
func (s softwareAPIStore) Verify() error                  { return nil }

type softwareAPIAuthority struct{ current windowssoftwarejob.Current }

func (a *softwareAPIAuthority) WithCurrent(_ context.Context, _ windowssoftwarejob.Binding, f func(windowssoftwarejob.Current) error) error {
	return f(a.current)
}

type softwareAPIReadiness struct{ r windowssoftwarejob.Readiness }

func (a softwareAPIReadiness) Readiness(context.Context, windowssoftwarejob.Binding, windowssoftwarejob.Selection) (windowssoftwarejob.Readiness, error) {
	return a.r, nil
}

type softwareAPIFixture struct {
	handler    *operatorHandler
	session    operatorauth.Session
	authority  *softwareAPIAuthority
	selection  windowssoftwarejob.Selection
	device, id string
}

func newSoftwareAPIFixture(t *testing.T, caps []operatorauth.Capability) softwareAPIFixture {
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
	b := windowssoftwarejob.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: namedDeviceID, IncarnationDigest: actionpermit.Digest([]byte("anchor")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(apiExecutorKey.Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("4", 32), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey))}
	c := windowssoftwarejob.Consent{Package: preparedMSITestSelection(), NativeAcceptanceDigest: actionpermit.Digest([]byte("native acceptance")), PackageReviewAccepted: true, Version: windowssoftwarejob.ConsentVersion, Scope: windowssoftwarejob.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: at + 3600}
	record, e := windowssoftwarejob.NewRecordWithExecutor(c, key.Public().(ed25519.PublicKey), apiExecutorKey.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := windowssoftwarejob.EncodeRecord(record)
	consent, _ := json.Marshal(c)
	s := softwareAPIStore{"jobs.json": raw, "started.json": consent, "receipt.json": consent}
	a := &softwareAPIAuthority{windowssoftwarejob.Current{Binding: b, LeafDigest: actionpermit.Digest([]byte("current")), LeafGeneration: 1, LeafNotBefore: at - 1, LeafNotAfter: at + 300, Enabled: true}}
	selection := preparedMSITestSelection()
	r := windowssoftwarejob.Readiness{Selection: selection, CapturedAt: at, PackageVerified: windowssoftwarejob.Yes, MachineAbsent: windowssoftwarejob.Yes, InstallerBusy: windowssoftwarejob.No, NativeAcceptance: windowssoftwarejob.Yes, PackageReviewAccepted: windowssoftwarejob.Yes, MaintenanceWindowEnd: at + 600}
	m, e := windowssoftwarejob.Open(s, a, softwareAPIReadiness{r}, key, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	app.mu.Lock()
	app.lanOnly = true
	app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: namedDeviceID, Platform: "windows"}}, nil }
	app.mu.Unlock()
	h := &operatorHandler{app: app, auth: auth, origin: "https://manager.invalid", authority: "manager.invalid", cookieName: operatorauth.CookieName, windowsSoftwareJobs: m}
	return softwareAPIFixture{h, session, a, selection, namedDeviceID, "software_" + strings.Repeat("6", 32)}
}

// In-process recorder only: these API fixtures never listen on a local socket.
func (f softwareAPIFixture) call(t *testing.T, method, suffix string, body any, change func(*http.Request)) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://manager.invalid/api/devices/"+f.device+"/windows-software-jobs"+suffix, bytes.NewReader(raw))
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
func TestWindowsSoftwareJobAPIRequestReviewApprovalAndStatus(t *testing.T) {
	f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
	code, v := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "package": f.selection}, nil)
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
func TestWindowsSoftwareJobAPINoPermissionPromotionAndHTTP(t *testing.T) {
	for _, caps := range [][]operatorauth.Capability{{operatorauth.Read}, {operatorauth.Read, operatorauth.ExecuteUpdates}, {operatorauth.Read, operatorauth.WindowsServiceControl}, {operatorauth.Read, operatorauth.WindowsUpdateInstall}} {
		f := newSoftwareAPIFixture(t, caps)
		if code, _ := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "package": f.selection}, nil); code != 403 {
			t.Fatal("existing capability promoted", code)
		}
	}
	f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
	f.handler.insecureHTTPTest = true
	if code, _ := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "package": f.selection}, nil); code != 409 {
		t.Fatal("plaintext mutation allowed", code)
	}
}
func TestWindowsSoftwareJobAPICSRFOriginActorRevocation(t *testing.T) {
	f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
	body := map[string]any{"requestId": f.id, "package": f.selection}
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
func TestWindowsSoftwareJobAPIDefaultOffAndNoExecutorIngress(t *testing.T) {
	f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
	f.handler.windowsSoftwareJobs = nil
	code, v := f.call(t, "GET", "", nil, nil)
	if code != 200 || v["available"] != false || v["reason"] != "executor_not_configured" {
		t.Fatal(code, v)
	}
	for _, op := range []string{"claim", "result", "install", "download", "reboot"} {
		r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-software-jobs/"+op, nil)
		if _, _, ok := windowsSoftwareJobRoute(r); ok {
			t.Fatal("unimplemented executor route exposed", op)
		}
	}
}

func TestWindowsSoftwareJobAPIBodyReadDoesNotHoldSessionGate(t *testing.T) {
	for _, op := range []string{"request", "preview", "approve"} {
		t.Run(op, func(t *testing.T) {
			f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
			raw := `{"requestId":"` + f.id + `"}`
			if op == "request" {
				encoded, _ := json.Marshal(map[string]any{"requestId": f.id, "package": f.selection})
				raw = string(encoded)
			}
			if op == "approve" {
				raw = `{"previewId":"` + f.id + `","previewDigest":"` + actionpermit.Digest([]byte("fixture")) + `","acknowledged":true}`
			}
			body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(raw)}
			r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-software-jobs/"+op, body)
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
				t.Fatal("slow software body blocked logout")
			}
			close(body.allow)
			<-done
			if w.Code != http.StatusUnauthorized {
				t.Fatal("revoked body reached software admission", w.Code)
			}
		})
	}
}

func TestWindowsSoftwareHistoryAndExactQueriesAreReadOnlyAndStrict(t *testing.T) {
	f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
	for _, query := range []string{"?jobId=", "?jobId=bad", "?jobId=bad;history=1", "?history=0", "?history=1&history=1", "?history=1&jobId=" + f.id} {
		if code, _ := f.call(t, "GET", query, nil, nil); code != 400 {
			t.Fatal("malformed exact query fell back", query, code)
		}
	}
	if code, _ := f.call(t, "GET", "?jobId="+f.id, nil, nil); code != 409 {
		t.Fatal("absent exact query fell back", code)
	}
	if code, v := f.call(t, "GET", "?history=1", nil, nil); code != 200 || len(v["jobs"].([]any)) != 0 || v["remainingCapacity"] != float64(windowssoftwarejob.MaxJobs) {
		t.Fatal(code, v)
	}
	code, v := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "package": f.selection}, nil)
	if code != 200 {
		t.Fatal(code, v)
	}
	code, v = f.call(t, "GET", "?history=1", nil, nil)
	if code != 200 || len(v["jobs"].([]any)) != 1 {
		t.Fatal(code, v)
	}
	raw, _ := json.Marshal(v)
	for _, private := range []string{"preview", "envelope", "signature", "publicKey", "actorId"} {
		if bytes.Contains(raw, []byte(`"`+private+`":`)) {
			t.Fatal("history leaked executable/review authority", private)
		}
	}
}

func preparedMSITestSelection() windowssoftwarejob.Selection {
	return windowssoftwarejob.Selection{SHA256: actionpermit.Digest([]byte("fixture")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture package", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "Fixture review"}
}

func TestWindowsSoftwarePackageBodyRejectsNestedAmbiguity(t *testing.T) {
	for _, kind := range []string{"duplicate", "case", "null", "path"} {
		t.Run(kind, func(t *testing.T) {
			f := newSoftwareAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsSoftwareInstall})
			body := map[string]any{"requestId": f.id, "package": f.selection}
			raw, _ := json.Marshal(body)
			switch kind {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"name":"Fixture package"`), []byte(`"name":"Fixture package","name":"Fixture package"`), 1)
			case "case":
				raw = bytes.Replace(raw, []byte(`"name":`), []byte(`"Name":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"name":"Fixture package"`), []byte(`"name":null`), 1)
			case "path":
				raw = bytes.Replace(raw, []byte(`"name":"Fixture package"`), []byte(`"name":"Fixture package","path":"C:\\arbitrary.msi"`), 1)
			}
			code, _ := f.call(t, "POST", "/request", body, func(r *http.Request) { r.Body = io.NopCloser(bytes.NewReader(raw)) })
			if code != 400 {
				t.Fatal("ambiguous package accepted", code)
			}
		})
	}
}
