package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func lanBody(revision string) map[string]any {
	return map[string]any{"expectedRevision": revision, "baseURL": "https://10.5.6.7:8443/v1", "model": "fixture-model", "apiKey": "", "approvedOrigin": "https://10.5.6.7:8443", "allowRemoteEvidence": true, "useLegacyMaxTokens": false, "acknowledgeLanDestination": true}
}
func encodeLANBody(t *testing.T, b map[string]any) string {
	t.Helper()
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

func TestLANAIRequiresExplicitIndependentApprovalsAndPreservesOldRoute(t *testing.T) {
	s := setup(t)
	view := aiView(t, s)
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"destination consent", func(b map[string]any) { b["acknowledgeLanDestination"] = false }},
		{"data consent", func(b map[string]any) { b["allowRemoteEvidence"] = false }},
		{"missing destination consent", func(b map[string]any) { delete(b, "acknowledgeLanDestination") }},
		{"origin substitution", func(b map[string]any) { b["approvedOrigin"] = "https://10.5.6.8:8443" }},
		{"plain HTTP", func(b map[string]any) {
			b["baseURL"] = "http://10.5.6.7:8443/v1"
			b["approvedOrigin"] = "http://10.5.6.7:8443"
		}},
		{"private hostname", func(b map[string]any) {
			b["baseURL"] = "https://model.example.test:8443/v1"
			b["approvedOrigin"] = "https://model.example.test:8443"
		}},
		{"no explicit port", func(b map[string]any) { b["baseURL"] = "https://10.5.6.7/v1"; b["approvedOrigin"] = "https://10.5.6.7" }},
		{"metadata", func(b map[string]any) {
			b["baseURL"] = "https://169.254.169.254:8443/v1"
			b["approvedOrigin"] = "https://169.254.169.254:8443"
		}},
		{"loopback", func(b map[string]any) {
			b["baseURL"] = "https://127.0.0.1:8443/v1"
			b["approvedOrigin"] = "https://127.0.0.1:8443"
		}},
		{"credential over operator HTTP", func(b map[string]any) { b["apiKey"] = "synthetic-key" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := lanBody(view.Revision)
			tc.edit(b)
			w := request(s, "POST", "/api/ai/config/lan", encodeLANBody(t, b), nil)
			if w.Code != 400 {
				t.Fatal("unexpected acceptance", w.Code, w.Body.String())
			}
			if aiView(t, s).Revision != view.Revision {
				t.Fatal("rejected settings changed state")
			}
		})
	}
	old := lanBody(view.Revision)
	delete(old, "acknowledgeLanDestination")
	if w := request(s, "POST", "/api/ai/config", encodeLANBody(t, old), nil); w.Code != 400 {
		t.Fatal("old route allowed private LAN", w.Code)
	}
	persist := lanBody(view.Revision)
	delete(persist, "acknowledgeLanDestination")
	persist["acknowledgeKeyStorage"] = false
	if w := request(s, "POST", "/api/ai/config/persistent", encodeLANBody(t, persist), nil); w.Code != 400 {
		t.Fatal("LAN silently accepted by persistent endpoint", w.Code)
	}
	valid := lanBody(view.Revision)
	duplicate := strings.TrimSuffix(encodeLANBody(t, valid), "}") + `,"acknowledgeLanDestination":true}`
	if w := request(s, "POST", "/api/ai/config/lan", duplicate, nil); w.Code != 400 {
		t.Fatal("duplicate consent accepted", w.Code)
	}
	for _, modify := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Del("Origin") }} {
		if w := request(s, "POST", "/api/ai/config/lan", encodeLANBody(t, valid), modify); w.Code != 403 {
			t.Fatal("missing origin/CSRF accepted", w.Code)
		}
	}
	w := request(s, "POST", "/api/ai/config/lan", encodeLANBody(t, valid), nil)
	if w.Code != 200 {
		t.Fatal("approved LAN rejected", w.Code, w.Body.String())
	}
	saved := aiView(t, s)
	if !saved.Configured || !saved.LANMode || saved.Storage != "memory-only" || !saved.ResetsOnRestart || !saved.AllowRemoteEvidence || saved.EndpointOrigin != "https://10.5.6.7:8443" {
		t.Fatal("wrong readback")
	}
	fresh, err := New(s.store, 8787, s.web, s.sampleDevice())
	if err != nil {
		t.Fatal(err)
	}
	if aiView(t, fresh).Configured {
		t.Fatal("LAN provider persisted")
	}
	if w = request(s, "POST", "/api/ai/config/lan", encodeLANBody(t, valid), nil); w.Code != 409 {
		t.Fatal("stale revision accepted", w.Code)
	}
	if strings.Contains(w.Body.String(), "synthetic-key") {
		t.Fatal("credential exposed")
	}
}

func TestLANAIRequiresAuthenticatedSharedAdministrator(t *testing.T) {
	o := newOperatorFixture(t, 0)
	b := lanBody("cfg-invalid")
	response, _ := o.call(t, "POST", "/api/ai/config/lan", b, "", nil)
	if response.StatusCode != 401 {
		t.Fatal("anonymous configuration accepted", response.StatusCode)
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	_, current := o.call(t, "GET", "/api/ai/config", nil, "", nil)
	b = lanBody(current["revision"].(string))
	response, _ = o.call(t, "POST", "/api/ai/config/lan", b, "", nil)
	if response.StatusCode != 403 {
		t.Fatal("missing CSRF accepted", response.StatusCode)
	}
	response, v := o.call(t, "POST", "/api/ai/config/lan", b, csrf, nil)
	if response.StatusCode != 200 || v["lanMode"] != true {
		t.Fatal("shared admin configuration rejected", response.StatusCode)
	}
	named, _ := namedOperatorFixture(t)
	login, v := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if login.StatusCode != 200 {
		t.Fatal("named fixture login", login.StatusCode)
	}
	response, _ = named.call(t, "POST", "/api/ai/config/lan", b, v["csrfToken"].(string), nil)
	if response.StatusCode != 403 {
		t.Fatal("named account granted AI configuration", response.StatusCode)
	}
}
