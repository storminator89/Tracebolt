package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowscontact"
)

type contactPolicySourceFixture struct {
	*fixtureWindowsContactSource
	guardCalls int
	failGuard  bool
}

func (f *contactPolicySourceFixture) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, fn func(func(time.Time) error) error) error {
	if len(expected) != 1 {
		return windowscontact.ErrInvalid
	}
	return fn(func(at time.Time) error {
		f.guardCalls++
		current := f.inputs[0]
		if ctx.Err() != nil || f.failGuard || !current.Authorized || current.InvitationID != expected[0].InvitationID || current.CertificateHash != expected[0].CertificateHash || !at.Before(current.AuthorityUntil) {
			return windowscontact.ErrInvalid
		}
		return nil
	})
}
func contactPolicyFixture(t *testing.T) (operatorFixture, *windowsContactMonitor, *contactPolicySourceFixture, string, string) {
	o := newOperatorFixture(t, time.Hour)
	m, base := installContactFixture(t, o)
	f := &contactPolicySourceFixture{fixtureWindowsContactSource: base}
	m.source = f
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	return o, m, f, "/api/devices/" + f.inputs[0].DeviceID + "/windows-contact", csrf
}
func contactPolicyBody() map[string]any {
	return map[string]any{"expectedRevision": 0, "requestId": strings.Repeat("4", 32), "graceSeconds": 300, "acknowledged": true}
}

func TestWindowsContactPolicyAPIExplicitGraceAndUnchangedReads(t *testing.T) {
	o, m, f, path, csrf := contactPolicyFixture(t)
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["schemaVersion"] != "tracebolt.windows-contact-view.v1" || v["policy"] != nil {
		t.Fatal(r.StatusCode, v)
	}
	r, v := o.call(t, "POST", path+"/policy", contactPolicyBody(), csrf, nil)
	if r.StatusCode != 200 || v["schemaVersion"] != "tracebolt.windows-contact-view.v2" || v["status"] != "unknown" {
		t.Fatal(r.StatusCode, v)
	}
	p := v["policy"].(map[string]any)
	if p["graceSeconds"] != float64(300) || p["revision"] != float64(1) || p["awaitingFreshReport"] != true || f.guardCalls < 2 {
		t.Fatal(p, f.guardCalls)
	}
	if r, _ = o.call(t, "POST", path+"/policy", contactPolicyBody(), csrf, nil); r.StatusCode != 200 {
		t.Fatal("exact replay", r.StatusCode)
	}
	f.now = f.now.Add(time.Second)
	f.inputs[0].Sequence++
	f.inputs[0].ReceivedAt = f.now
	if err := m.evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, v = o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["policy"].(map[string]any)["awaitingFreshReport"] != false {
		t.Fatal(r.StatusCode, v)
	}
	base := f.now
	for sec := 30; sec <= 390; sec += 30 {
		f.now = base.Add(time.Duration(sec) * time.Second)
		if err := m.evaluate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if sec == 180 {
			if r, v = o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" || len(v["incidents"].([]any)) != 0 {
				t.Fatal("grace made stale source recent", r.StatusCode, v)
			}
		}
	}
	if r, v = o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "overdue" || len(v["incidents"].([]any)) != 1 {
		t.Fatal(r.StatusCode, v)
	}
	incident := v["incidents"].([]any)[0].(map[string]any)
	if incident["graceSeconds"] != float64(300) || incident["policyRevision"] != float64(1) {
		t.Fatal(incident)
	}
	if output := os.Getenv("TRACEBOLT_CONTACT_POLICY_FIXTURE"); output != "" {
		raw, _ := json.Marshal(v)
		if err := os.WriteFile(output, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWindowsContactPolicyAPIRejectsUnreviewedOrStaleWrites(t *testing.T) {
	for _, kind := range []string{"csrf", "origin", "consent", "threshold", "revision", "guard", "authority", "query", "force-query", "method"} {
		t.Run(kind, func(t *testing.T) {
			o, _, f, path, csrf := contactPolicyFixture(t)
			body := contactPolicyBody()
			method := "POST"
			path += "/policy"
			switch kind {
			case "csrf":
				csrf = ""
			case "consent":
				body["acknowledged"] = false
			case "threshold":
				body["graceSeconds"] = 121
			case "revision":
				body["expectedRevision"] = 1
			case "guard":
				f.failGuard = true
			case "authority":
				f.inputs[0].Authorized = false
			case "query":
				path += "?x=1"
			case "force-query":
				path += "?"
			case "method":
				method = "GET"
			}
			if r, _ := o.call(t, method, path, body, csrf, func(r *http.Request) {
				if kind == "origin" {
					r.Header.Set("Origin", "https://other.invalid")
				}
			}); r.StatusCode == 200 {
				t.Fatal("unsafe write accepted")
			}
			state, err := o.app.store.WindowsContactState(context.Background(), f.inputs[0].DeviceID)
			if err != nil || state.Policy != nil {
				t.Fatal(err, state)
			}
		})
	}
}

func TestWindowsContactPolicyNamedReaderCannotWrite(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	m, base := installContactFixture(t, o)
	m.source = &contactPolicySourceFixture{fixtureWindowsContactSource: base}
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	path := "/api/devices/" + base.inputs[0].DeviceID + "/windows-contact"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 {
		t.Fatal("named reader lost existing read", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", path+"/policy", contactPolicyBody(), session["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named reader changed policy", r.StatusCode)
	}
	state, err := o.app.store.WindowsContactState(context.Background(), base.inputs[0].DeviceID)
	if err != nil || state.Policy != nil {
		t.Fatal("named request changed stored state", err, state)
	}
}

func TestWindowsContactPolicyStrictDecoder(t *testing.T) {
	for _, raw := range []string{`{}`, `{"expectedRevision":0,"requestId":"44444444444444444444444444444444","graceSeconds":300,"acknowledged":true,"extra":1}`, `{"expectedRevision":0,"requestId":"44444444444444444444444444444444","graceSeconds":300,"acknowledged":true,"acknowledged":true}`, `{"expectedRevision":null,"requestId":"44444444444444444444444444444444","graceSeconds":300,"acknowledged":true}`, `{"expectedRevision":0,"requestId":"44444444444444444444444444444444","graceSeconds":300.5,"acknowledged":true}`} {
		r := httptest.NewRequest(http.MethodPost, "https://fixture.invalid/", strings.NewReader(raw))
		w := httptest.NewRecorder()
		var out windowscontact.PolicyRequest
		if readWindowsContactPolicyRequest(w, r, &out) || w.Code != 400 {
			t.Fatal(raw, w.Code)
		}
	}
}

func TestWindowsContactPolicyCommittedButUnconfirmedReconcilesByRead(t *testing.T) {
	o, _, f, path, csrf := contactPolicyFixture(t)
	f.reads = 0
	f.onRead = func(n int) {
		if n == 2 {
			f.inputs[0].Authorized = false
		}
	}
	if r, _ := o.call(t, "POST", path+"/policy", contactPolicyBody(), csrf, nil); r.StatusCode != 409 {
		t.Fatal("expected unconfirmed final authority", r.StatusCode)
	}
	state, err := o.app.store.WindowsContactState(context.Background(), f.inputs[0].DeviceID)
	if err != nil || state.PolicyRevision() != 1 || state.Policy.LastRequestID != strings.Repeat("4", 32) {
		t.Fatal("commit was not preserved for reconciliation", err, state)
	}
	f.onRead = nil
	f.inputs[0].Authorized = true
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["policy"].(map[string]any)["lastRequestId"] != strings.Repeat("4", 32) {
		t.Fatal(r.StatusCode, v)
	}
}
