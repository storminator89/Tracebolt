package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateLANCARequiresHTTPSApprovalAndPreventsDowngrade(t *testing.T) {
	ca, _, _, _ := operatorCertificates(t)
	block, _ := pem.Decode(ca)
	sum := sha256.Sum256(block.Bytes)
	hash := hex.EncodeToString(sum[:])
	privateBody := func(revision string) map[string]any {
		b := lanBody(revision)
		b["caPem"] = string(ca)
		b["expectedCaSha256"] = hash
		b["acknowledgeCaFingerprint"] = true
		return b
	}
	dev := setup(t)
	if w := request(dev, "POST", "/api/ai/config/lan-private-ca", encodeLANBody(t, privateBody(aiView(t, dev).Revision)), nil); w.Code != 400 {
		t.Fatal("HTTP development import accepted", w.Code)
	}
	// Use the actual authenticated HTTP-test handler, not just a mocked TLS flag.
	httpFixture := newOperatorFixture(t, 0)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash()})
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewUnstartedServer(nil)
	handler, err := NewLANOperatorHandler(httpFixture.app, LANOperatorConfig{Origin: "http://" + plain.Listener.Addr().String(), Auth: auth, Registry: httpFixture.registry, InsecureHTTPTest: true, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	plain.Config.Handler = handler
	plain.Start()
	defer plain.Close()
	client := plain.Client()
	client.Jar, _ = cookiejar.New(nil)
	httpFixture.server, httpFixture.client = plain, client
	_, httpSession := httpFixture.login(t)
	_, httpCurrent := httpFixture.call(t, "GET", "/api/ai/config", nil, "", nil)
	if r, _ := httpFixture.call(t, "POST", "/api/ai/config/lan-private-ca", privateBody(httpCurrent["revision"].(string)), httpSession["csrfToken"].(string), nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("authenticated HTTP-test import accepted", r.StatusCode)
	}
	o := newOperatorFixture(t, 0)
	if r, _ := o.call(t, "POST", "/api/ai/config/lan-private-ca", privateBody("cfg-invalid"), "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous import accepted", r.StatusCode)
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	_, current := o.call(t, "GET", "/api/ai/config", nil, "", nil)
	revision := current["revision"].(string)
	o.app.ai.mu.Lock()
	o.app.ai.proactive.enabled = true // synthetic existing approval; must not follow a provider change
	o.app.ai.proactive.configRevision = revision
	o.app.ai.mu.Unlock()
	for _, edit := range []func(map[string]any){func(b map[string]any) { b["acknowledgeCaFingerprint"] = false }, func(b map[string]any) { b["expectedCaSha256"] = strings.ToUpper(hash) }, func(b map[string]any) { b["caPem"] = string(ca) + string(ca) }, func(b map[string]any) { b["caPem"] = string(ca) + strings.Repeat(" ", 4096) }, func(b map[string]any) { b["allowRemoteEvidence"] = false }, func(b map[string]any) { b["apiKey"] = hash }} {
		b := privateBody(revision)
		edit(b)
		if r, _ := o.call(t, "POST", "/api/ai/config/lan-private-ca", b, csrf, nil); r.StatusCode != 400 {
			t.Fatal("invalid private CA accepted", r.StatusCode)
		}
	}
	r, result := o.call(t, "POST", "/api/ai/config/lan-private-ca", privateBody(revision), csrf, nil)
	if r.StatusCode != 200 || result["lanPrivateCaSha256"] != hash || result["lanMode"] != true {
		t.Fatal("valid import rejected", r.StatusCode, result)
	}
	o.app.ai.mu.Lock()
	if o.app.ai.proactive.enabled {
		t.Fatal("old proactive scope survived provider change")
	}
	o.app.ai.mu.Unlock()
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), string(ca)) || strings.Contains(string(raw), "caPem") {
		t.Fatal("CA material exposed")
	}
	revision = result["revision"].(string)
	for _, path := range []string{"/api/ai/config", "/api/ai/config/persistent", "/api/ai/config/lan", "/api/ai/config/lan-private-ca"} {
		b := lanBody(revision)
		if path == "/api/ai/config" || path == "/api/ai/config/persistent" {
			delete(b, "acknowledgeLanDestination")
			b["baseURL"] = "http://127.0.0.1:11434/v1"
			b["approvedOrigin"] = "http://127.0.0.1:11434"
		}
		if path == "/api/ai/config/persistent" {
			b["acknowledgeKeyStorage"] = false
		}
		if path == "/api/ai/config/lan-private-ca" {
			b = privateBody(revision)
		}
		if r, _ := o.call(t, "POST", path, b, csrf, nil); r.StatusCode != 409 {
			t.Fatal("pin replacement accepted", path, r.StatusCode)
		}
	}
	_, current = o.call(t, "GET", "/api/ai/config", nil, "", nil)
	if current["revision"] != revision || current["lanPrivateCaSha256"] != hash {
		t.Fatal("rejected save altered state")
	}
	r, result = o.call(t, "POST", "/api/ai/config/clear", map[string]any{"expectedRevision": revision}, csrf, nil)
	if r.StatusCode != 200 || result["lanPrivateCaSha256"] != nil {
		t.Fatal("explicit clear failed", r.StatusCode)
	}
	r, _ = o.call(t, "POST", "/api/ai/config/lan", lanBody(result["revision"].(string)), csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal("save after clear failed", r.StatusCode)
	}
}
