package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"net/http"
	"strings"
	"testing"
	"time"
)

type windowsActionAPIFixture struct {
	record    windowsactionjob.Record
	at        time.Time
	key       ed25519.PrivateKey
	next      int
	approvals int
}

func (f *windowsActionAPIFixture) ViewAt(context.Context, string) (windowsactionjob.Record, time.Time, error) {
	return f.record, f.at, nil
}
func (f *windowsActionAPIFixture) Preview(_ context.Context, device, actor, target, op string) (windowsactionjob.Record, error) {
	f.next++
	e := f.record.MakePreview("action_"+strings.Repeat(string(rune('3'+f.next)), 32), actor, target, op, f.at)
	return f.record, e
}
func (f *windowsActionAPIFixture) Approve(_ context.Context, device, id, digest, actor string) (windowsactionjob.Record, error) {
	e := f.record.Approve(id, digest, actor, f.at, func(p windowsaction.Permit) ([]byte, error) {
		f.approvals++
		m, e := windowsaction.SigningMessage(p)
		if e != nil {
			return nil, e
		}
		return windowsaction.Encode(p, ed25519.Sign(f.key, m))
	})
	return f.record, e
}
func (f *windowsActionAPIFixture) TransportProfile() string { return "production-tls" }
func (f *windowsActionAPIFixture) Available() bool          { return true }
func windowsActionOperator(t *testing.T) (operatorFixture, *windowsActionAPIFixture, string) {
	t.Helper()
	o := newOperatorFixture(t, 0)
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsServiceControl}}}})
	if e != nil {
		t.Fatal(e)
	}
	h := o.server.Config.Handler.(*operatorHandler)
	h.auth = auth
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: namedDeviceID}}, nil }
	o.app.mu.Unlock()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	at := time.Now().UTC()
	b := windowsaction.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), EndpointID: namedDeviceID, KeyID: windowsaction.Digest(key.Public().(ed25519.PublicKey)), IncarnationDigest: windowsaction.Digest([]byte("cert")), InstallationID: "broker_" + strings.Repeat("2", 32), GrantDigest: windowsaction.Digest([]byte("grant")), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("config"))}
	r, e := windowsactionjob.New(b, key.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Report(windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}, at); e != nil {
		t.Fatal(e)
	}
	f := &windowsActionAPIFixture{record: r, at: at, key: key}
	h.windowsActions = f
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	return o, f, login["csrfToken"].(string)
}
func TestWindowsServiceActionAPIThreeOpsAndExactApproval(t *testing.T) {
	for _, op := range []string{"start", "stop", "restart"} {
		t.Run(op, func(t *testing.T) {
			o, f, csrf := windowsActionOperator(t)
			base := "/api/devices/" + namedDeviceID + "/windows-service-actions"
			r, v := o.call(t, "POST", base+"/preview", map[string]string{"target": "FixtureService", "operation": op}, csrf, nil)
			if r.StatusCode != 200 || v["preview"] == nil {
				t.Fatal("preview", r.StatusCode, v)
			}
			p := v["preview"].(map[string]any)
			body := map[string]any{"previewId": p["id"], "previewDigest": p["digest"]}
			for n := 0; n < 2; n++ {
				r, v = o.call(t, "POST", base+"/approve", body, csrf, nil)
				if r.StatusCode != 200 || v["job"] == nil {
					t.Fatal("approval", r.StatusCode, v)
				}
				raw, _ := json.Marshal(v)
				if strings.Contains(string(raw), "envelope\"") || strings.Contains(string(raw), "signature") || strings.Contains(string(raw), "publicKey") {
					t.Fatal("execution material in operator view")
				}
			}
			if f.approvals != 1 {
				t.Fatal("repeated approval signed twice")
			}
		})
	}
}
func TestWindowsServiceActionAPICSFRActorAndStaleGuards(t *testing.T) {
	o, f, csrf := windowsActionOperator(t)
	base := "/api/devices/" + namedDeviceID + "/windows-service-actions"
	body := map[string]string{"target": "FixtureService", "operation": "restart"}
	for _, tc := range []struct {
		csrf   string
		body   any
		modify func(*http.Request)
		code   int
	}{{"bad", body, nil, 403}, {csrf, body, func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403}, {csrf, map[string]string{"target": "FixtureService", "operation": "restart", "actorId": namedActorID}, nil, 400}, {csrf, map[string]string{"target": "FixtureService", "operation": "shell"}, nil, 400}} {
		r, _ := o.call(t, "POST", base+"/preview", tc.body, tc.csrf, tc.modify)
		if r.StatusCode != tc.code {
			t.Fatal("guard", r.StatusCode, tc.code)
		}
	}
	_, v := o.call(t, "POST", base+"/preview", body, csrf, nil)
	p := v["preview"].(map[string]any)
	f.at = f.at.Add(time.Minute)
	r, _ := o.call(t, "POST", base+"/approve", map[string]any{"previewId": p["id"], "previewDigest": p["digest"]}, csrf, nil)
	if r.StatusCode != 409 || f.approvals != 0 {
		t.Fatal("expired approved")
	}
}
func TestWindowsServiceActionAPILinuxGrantIsInsufficient(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	r, _ := o.call(t, "POST", "/api/devices/"+namedDeviceID+"/windows-service-actions/preview", map[string]string{"target": "FixtureService", "operation": "start"}, login["csrfToken"].(string), nil)
	if r.StatusCode != 403 {
		t.Fatal("Linux restart grant promoted", r.StatusCode)
	}
}
