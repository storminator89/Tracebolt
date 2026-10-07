package api

import (
	"context"
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
	"localrmm/internal/packageupdate"
)

func packageOperatorFixture(t *testing.T, caps ...operatorauth.Capability) operatorFixture {
	t.Helper()
	o := newOperatorFixture(t, 0)
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "updater", PasswordHash: testOperatorHash(), Capabilities: append([]operatorauth.Capability{operatorauth.Read}, caps...)}}})
	if e != nil {
		t.Fatal(e)
	}
	o.server.Config.Handler.(*operatorHandler).auth = auth
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: namedDeviceID}}, nil }
	o.app.mu.Unlock()
	return o
}
func packageLogin(t *testing.T, o operatorFixture) string {
	t.Helper()
	r, v := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "updater", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	return v["csrfToken"].(string)
}
func TestPackageUpdatesStayInertBehindRealOperatorBoundary(t *testing.T) {
	o := packageOperatorFixture(t, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates)
	base := "/api/devices/" + namedDeviceID + "/package-updates"
	if r, _ := o.call(t, "GET", base, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read", r.StatusCode)
	}
	csrf := packageLogin(t, o)
	r, v := o.call(t, "GET", base, nil, "", nil)
	if r.StatusCode != 200 || len(v) != 8 || v["schemaVersion"] != packageupdate.ViewVersion || v["deviceId"] != namedDeviceID || v["available"] != false || v["reason"] != "native_adapter_unavailable" || v["preview"] != nil || v["job"] != nil {
		t.Fatal("fabricated capability/evidence", r.StatusCode, v)
	}
	prepare := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	approve := packageupdate.ApprovalRequest{RequestID: prepare.RequestID, PreviewDigest: actionpermit.Digest([]byte("fixture"))}
	for _, tc := range []struct {
		method, path, token string
		body                any
		modify              func(*http.Request)
		want                int
	}{
		{"POST", base + "/prepare", csrf, prepare, nil, 409},
		{"POST", base + "/approve", csrf, approve, nil, 409},
		{"POST", base + "/prepare", "bad", prepare, nil, 403},
		{"POST", base + "/prepare", csrf, prepare, func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403},
		{"GET", base + "/prepare", "", nil, nil, 405},
		{"POST", base, csrf, prepare, nil, 405},
		{"GET", base + "?plan=forged", "", nil, nil, 400},
		{"GET", "/api/devices/agent_22222222222222222222222222222222/package-updates", "", nil, nil, 404},
	} {
		r, v = o.call(t, tc.method, tc.path, tc.body, tc.token, tc.modify)
		if r.StatusCode != tc.want {
			t.Fatalf("%s %s: %d != %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
		if tc.want == 409 && v["error"].(map[string]any)["code"] != "package_update_unavailable" {
			t.Fatal(v)
		}
	}
	_, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil)
	if r, _ := o.call(t, "GET", base, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("logout read", r.StatusCode)
	}
}
func TestPackageUpdatesCapabilitiesAreIndependentAndSharedCannotMutate(t *testing.T) {
	base := "/api/devices/" + namedDeviceID + "/package-updates"
	for _, caps := range [][]operatorauth.Capability{nil, {operatorauth.PlanUpdates}, {operatorauth.ExecuteUpdates}, {operatorauth.RestartService}} {
		o := packageOperatorFixture(t, caps...)
		csrf := packageLogin(t, o)
		for _, op := range []string{"prepare", "approve"} {
			want := 403
			for _, c := range caps {
				if op == "prepare" && c == operatorauth.PlanUpdates || op == "approve" && c == operatorauth.ExecuteUpdates {
					want = 400
				}
			}
			if r, _ := o.call(t, "POST", base+"/"+op, map[string]any{}, csrf, nil); r.StatusCode != want {
				t.Fatal(caps, op, r.StatusCode, want)
			}
		}
	}
	o := newOperatorFixture(t, 0)
	_, v := o.login(t)
	for _, op := range []string{"prepare", "approve"} {
		if r, _ := o.call(t, "POST", base+"/"+op, map[string]any{}, v["csrfToken"].(string), nil); r.StatusCode != 403 {
			t.Fatal("shared authority", r.StatusCode)
		}
	}
}
func TestPackageUpdateRequestRejectsEvidenceAndNestedAliases(t *testing.T) {
	o := packageOperatorFixture(t, operatorauth.PlanUpdates)
	csrf := packageLogin(t, o)
	path := "/api/devices/" + namedDeviceID + "/package-updates/prepare"
	for _, raw := range []string{
		`{"requestId":"update_11111111111111111111111111111111","packages":[{"name":"sample-bin","name":"other","architecture":"amd64"}]}`,
		`{"requestId":"update_11111111111111111111111111111111","packages":[{"Name":"sample-bin","architecture":"amd64"}]}`,
		`{"requestId":"update_11111111111111111111111111111111","packages":[{"name":"sample-bin","architecture":"amd64","archive":"/tmp/x.deb"}]}`,
		`{"requestId":"update_11111111111111111111111111111111","packages":[{"name":"sample-bin","architecture":"amd64"}],"plan":{}}`,
		`{"requestId":"update_11111111111111111111111111111111","packages":null}`,
	} {
		r, _ := o.call(t, "POST", path, map[string]any{}, csrf, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		})
		if r.StatusCode != 400 {
			t.Fatal("accepted unsafe shape", r.StatusCode)
		}
	}
	many := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: make([]packageupdate.Selection, 33)}
	if r, _ := o.call(t, "POST", path, many, csrf, nil); r.StatusCode != 400 {
		t.Fatal("widened bound", r.StatusCode)
	}
	huge := map[string]any{"requestId": strings.Repeat("x", packageupdate.MaxPrepareBytes), "packages": []any{}}
	if r, _ := o.call(t, "POST", path, huge, csrf, nil); r.StatusCode != 413 {
		t.Fatal("body bound", r.StatusCode)
	}
}
func TestPackageUpdateRoutesAreExact(t *testing.T) {
	base := "/api/devices/" + namedDeviceID + "/package-updates"
	for _, p := range []string{base + "/prepare/extra", base + "/approve/extra", base + "//approve", base + "-extra/prepare", base + "/execute", base + "/cancel", base + "/"} {
		if _, _, ok := packageUpdateRoute(httptest.NewRequest("POST", p, nil)); ok {
			t.Fatal("broad route", p)
		}
	}
}
func TestPackageUpdateGoViewContract(t *testing.T) {
	o := packageOperatorFixture(t)
	packageLogin(t, o)
	_, v := o.call(t, "GET", "/api/devices/"+namedDeviceID+"/package-updates", nil, "", nil)
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var view packageupdate.View
	if json.Unmarshal(raw, &view) != nil || view.SchemaVersion != packageupdate.ViewVersion || view.ServerNow.IsZero() {
		t.Fatal("contract mismatch")
	}
}

func TestPackageUpdateBodyReadDoesNotHoldSessionGate(t *testing.T) {
	for _, op := range []string{"prepare", "approve"} {
		t.Run(op, func(t *testing.T) {
			o := packageOperatorFixture(t, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates)
			h := o.server.Config.Handler.(*operatorHandler)
			session, e := h.auth.LoginNamed(context.Background(), "127.0.0.1", "updater", operatorFixturePassword)
			if e != nil {
				t.Fatal(e)
			}
			raw := `{"requestId":"update_11111111111111111111111111111111","packages":[{"name":"sample-bin","architecture":"amd64"}]}`
			if op == "approve" {
				b, _ := json.Marshal(packageupdate.ApprovalRequest{RequestID: "update_11111111111111111111111111111111", PreviewDigest: actionpermit.Digest([]byte("fixture"))})
				raw = string(b)
			}
			body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(raw)}
			r := httptest.NewRequest("POST", o.server.URL+"/api/devices/"+namedDeviceID+"/package-updates/"+op, body)
			r.Header.Set("Origin", o.server.URL)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", session.CSRFToken)
			active := func() bool { _, e := h.auth.Lookup(session.Token); return e == nil }
			r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: active}))
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { h.packageUpdates(w, r); close(done) }()
			<-body.started
			logout := make(chan struct{})
			go func() { h.auth.Logout(session.Token); close(logout) }()
			select {
			case <-logout:
			case <-time.After(time.Second):
				close(body.allow)
				<-done
				t.Fatal("slow package body blocked logout")
			}
			close(body.allow)
			<-done
			if w.Code != 401 {
				t.Fatal("revoked body reached admission", w.Code)
			}
		})
	}
}
