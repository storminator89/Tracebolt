package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
)

func TestCustomersAdminSessionCASAndPrivateCatalog(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f := newFleetGroupSource()
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	path := "/api/customers"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read", r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	input := map[string]any{"name": "Customer A", "expectedRevision": 0}
	if r, _ := o.call(t, "POST", path, input, "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", path, input, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("wrong origin", r.StatusCode)
	}
	r, v := o.call(t, "POST", path, input, csrf, nil)
	if r.StatusCode != 200 || v["schemaVersion"] != "tracebolt.customers.v1" {
		t.Fatal(r.StatusCode, v)
	}
	items := v["customers"].([]any)
	if len(items) != 1 {
		t.Fatal(items)
	}
	first := items[0].(map[string]any)
	if len(first) != 3 || first["name"] != "Customer A" || first["revision"] != float64(1) {
		t.Fatal(first)
	}
	id := first["id"].(string)
	if r, _ = o.call(t, "POST", path+"/"+id, map[string]any{"name": "Wrong", "expectedRevision": 2}, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision accepted", r.StatusCode)
	}
	if r, v = o.call(t, "POST", path+"/"+id, map[string]any{"name": "Customer B", "expectedRevision": 1}, csrf, nil); r.StatusCode != 200 || v["customers"].([]any)[0].(map[string]any)["revision"] != float64(2) {
		t.Fatal("rename", r.StatusCode, v)
	}
	for _, suffix := range []string{"?x=1", "?", "/extra/path"} {
		if r, _ = o.call(t, "GET", path+suffix, nil, "", nil); r.StatusCode == 200 {
			t.Fatal("ambiguous route", suffix)
		}
	}
	if r, _ = o.call(t, "POST", path, map[string]any{"name": "Name", "expectedRevision": 0, "site": "unexpected"}, csrf, nil); r.StatusCode != 400 {
		t.Fatal("unknown input accepted", r.StatusCode)
	}
	if r, _ = o.call(t, "DELETE", path+"/"+id, nil, csrf, nil); r.StatusCode != 405 {
		t.Fatal("deletion allowed", r.StatusCode)
	}
	f.issuerEnd = f.now
	if r, _ = o.call(t, "GET", path, nil, "", nil); r.StatusCode != 503 {
		t.Fatal("expired authority accepted", r.StatusCode)
	}
	named, _ := namedOperatorFixture(t)
	named.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{newFleetGroupSource()}
	named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r, _ = named.call(t, "GET", path, nil, "", nil); r.StatusCode != 403 {
		t.Fatal("named read allowed", r.StatusCode)
	}
}

type customerChangingSource struct {
	*fixtureFleetGroupSource
	reads int
}

func (s *customerChangingSource) Binding() enrollmentstate.Binding {
	s.reads++
	b := s.fixtureFleetGroupSource.Binding()
	if s.reads > 2 {
		b.Origin = "https://other.invalid"
	}
	return b
}

func TestCustomerFinalManagerBindingCheck(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	h := o.server.Config.Handler.(*operatorHandler)
	f := &customerChangingSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h.fleetGroupSources = []fleetGroupSource{f}
	manager := monitoringManager(f.fixtureFleetGroupSource.binding)
	_, err := o.app.store.SaveCustomer(context.Background(), manager, "customer_11111111111111111111111111111111", "Private name", 0, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", o.server.URL+"/api/customers", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{origin: o.server.URL, active: func() bool { return true }}))
	w := httptest.NewRecorder()
	h.customersAPI(w, r)
	if w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("Private name")) {
		t.Fatal("changed manager leaked catalog", w.Code, w.Body.String())
	}
}

func TestCustomerFinalSessionCheckAndCommittedUncertainty(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	h := o.server.Config.Handler.(*operatorHandler)
	f := newFleetGroupSource()
	h.fleetGroupSources = []fleetGroupSource{f}
	session, err := h.auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest("GET", o.server.URL+"/api/customers", nil)
	get = get.WithContext(context.WithValue(get.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: func() bool { return false }}))
	response := httptest.NewRecorder()
	h.customersAPI(response, get)
	if response.Code != 401 || bytes.Contains(response.Body.Bytes(), []byte("customers")) {
		t.Fatal("expired read was exposed", response.Code, response.Body.String())
	}

	// The lease and both pre-commit guards succeed, then the session expires.
	// The response must be withheld, even though the record was committed.
	checks := 0
	post := httptest.NewRequest("POST", o.server.URL+"/api/customers", bytes.NewBufferString(`{"name":"After commit","expectedRevision":0}`))
	post.Header.Set("Origin", o.server.URL)
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("X-CSRF-Token", session.CSRFToken)
	post = post.WithContext(context.WithValue(post.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: func() bool { checks++; return checks <= 4 }}))
	response = httptest.NewRecorder()
	h.customersAPI(response, post)
	if response.Code != 401 || bytes.Contains(response.Body.Bytes(), []byte("After commit")) {
		t.Fatal("expired response exposed", checks, response.Code, response.Body.String())
	}
	items, err := o.app.store.Customers(context.Background(), monitoringManager(f.binding))
	if err != nil || len(items) != 1 || items[0].Name != "After commit" {
		t.Fatal("post-commit state must be reconciled", items, err)
	}
}

func TestCustomerManagerRejectsChangedBindingAndExpiredIssuer(t *testing.T) {
	first, second := newFleetGroupSource(), newFleetGroupSource()
	second.now = first.now
	if _, _, err := customerManager(context.Background(), []fleetGroupSource{first, second}); err != nil {
		t.Fatal("consistent manager unavailable", err)
	}
	second.binding.Origin = "https://other.invalid"
	if _, _, err := customerManager(context.Background(), []fleetGroupSource{first, second}); err == nil {
		t.Fatal("different manager origin accepted")
	}
	second.binding = first.binding
	second.issuerEnd = first.now
	if _, _, err := customerManager(context.Background(), []fleetGroupSource{first, second}); err == nil {
		t.Fatal("expired issuer accepted")
	}
}
