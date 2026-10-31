package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/store"
)

// Customer metadata is deliberately not a tenant or a collection/action grant.
// Exercise the actual shared-admin assignment request, then compare the same
// authenticated observations and authority before and after that one mutation.
func TestCustomerOrganizationAssignmentPreservesDataAndAuthority(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	h := o.server.Config.Handler.(*operatorHandler)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h.fleetGroupSources = []fleetGroupSource{source}
	outside := source.devices[0]
	outside.ID, outside.Name = "agent_"+strings.Repeat("e", 32), "Other customer fixture"
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) {
		return []model.Device{source.devices[0], outside}, nil
	}
	o.app.mu.Unlock()
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	response, catalog := o.call(t, http.MethodPost, "/api/customers", map[string]any{"name": "Organizational fixture", "expectedRevision": 0}, csrf, nil)
	if response.StatusCode != http.StatusOK || len(catalog["customers"].([]any)) != 1 {
		t.Fatal("customer fixture creation failed", response.StatusCode)
	}
	customer := catalog["customers"].([]any)[0].(map[string]any)["id"].(string)
	response, view := o.call(t, http.MethodGet, "/api/customer-windows-assignments", nil, "", nil)
	if response.StatusCode != http.StatusOK || len(view["devices"].([]any)) != 1 {
		t.Fatal("assignment fixture unavailable", response.StatusCode)
	}
	device := view["devices"].([]any)[0].(map[string]any)
	body := map[string]any{"customerId": customer, "customerRevision": 1, "deviceId": device["deviceId"], "identity": device["identity"], "acknowledged": true}
	_, beforeDevices := o.call(t, http.MethodGet, "/api/devices", nil, "", nil)
	_, beforeCapabilities := o.call(t, http.MethodGet, "/api/capabilities", nil, "", nil)
	beforeSnapshots, err := source.Snapshots(context.Background())
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	beforeSource, err := json.Marshal([]any{source.devices, source.inputs, beforeSnapshots})
	if err != nil {
		t.Fatal("fixture source snapshot failed")
	}
	// Strict assignment input cannot smuggle any additional authority, and every
	// rejected request must leave the create-only assignment slot unused.
	for _, field := range []string{"scope", "capabilities", "collectionProfile", "actorId", "tenantId"} {
		injected := map[string]any{}
		for key, value := range body {
			injected[key] = value
		}
		injected[field] = "fixture-ungranted-authority"
		if response, _ = o.call(t, http.MethodPost, "/api/customer-windows-assignments", injected, csrf, nil); response.StatusCode != http.StatusBadRequest {
			t.Fatal("assignment accepted an authority field", field, response.StatusCode)
		}
	}
	if response, assigned := o.call(t, http.MethodPost, "/api/customer-windows-assignments", body, csrf, nil); response.StatusCode != http.StatusOK || assigned["devices"].([]any)[0].(map[string]any)["customerId"] != customer {
		t.Fatal("reviewed organizational assignment failed", response.StatusCode)
	}
	response, afterDevices := o.call(t, http.MethodGet, "/api/devices", nil, "", nil)
	if response.StatusCode != http.StatusOK || afterDevices["total"] != float64(2) || !reflect.DeepEqual(beforeDevices, afterDevices) {
		t.Fatal("customer assignment changed already-authorized inventory")
	}
	response, afterCapabilities := o.call(t, http.MethodGet, "/api/capabilities", nil, "", nil)
	if response.StatusCode != http.StatusOK || !reflect.DeepEqual(beforeCapabilities, afterCapabilities) {
		t.Fatal("customer assignment changed manager capabilities")
	}
	_, afterSession := o.call(t, http.MethodGet, "/api/auth/session", nil, "", nil)
	for _, field := range []string{"loginMode", "actorId", "capabilities", "csrfToken", "expiresAt"} {
		if !reflect.DeepEqual(session[field], afterSession[field]) {
			t.Fatal("customer assignment changed session authority", field)
		}
	}
	afterSnapshots, err := source.Snapshots(context.Background())
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	afterSource, err := json.Marshal([]any{source.devices, source.inputs, afterSnapshots})
	if err != nil || !bytes.Equal(beforeSource, afterSource) || len(o.registry.List()) != 0 {
		t.Fatal("customer assignment changed enrollment, source or trust authority")
	}
	// Customer query parameters are not server-side filters or rights. The
	// canonical API rejects them rather than pretending they isolate a customer.
	for _, path := range []string{"/api/devices", "/api/overview", "/api/capabilities"} {
		if response, _ := o.call(t, http.MethodGet, path+"?customerId="+customer, nil, "", nil); response.StatusCode != http.StatusBadRequest {
			t.Fatal("customer query was treated as a supported boundary", path, response.StatusCode)
		}
	}
}

func TestCustomerOrganizationMetadataCannotPromoteNamedOrAnonymousAuthority(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	h := o.server.Config.Handler.(*operatorHandler)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal("fixture admission failed")
	}
	id := source.inputs[0].DeviceID
	customer := "customer_" + strings.Repeat("7", 32)
	_, login := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	csrf := login["csrfToken"].(string)
	denied := []namedAdministrationRoute{
		{http.MethodGet, "/api/customers"},
		{http.MethodPost, "/api/customers"},
		{http.MethodGet, "/api/customer-windows-assignments"},
		{http.MethodPost, "/api/customer-windows-assignments"},
		{http.MethodPost, "/api/lan/agents/approve"},
		{http.MethodPost, "/api/windows/enrollment/invitations"},
		{http.MethodPost, "/api/devices/" + id + "/journal/create"},
		{http.MethodPost, "/api/devices/" + id + "/windows-service-actions/preview"},
		{http.MethodPost, "/api/cases/case-demo-win-01-service/analyze"},
		{http.MethodPost, "/api/ai/config"},
	}
	check := func(phase string) {
		t.Helper()
		for _, route := range denied {
			body := map[string]any{"customerId": customer, "scope": "all", "actorId": namedActorID}
			if route.method == http.MethodGet {
				body = nil
			}
			response, result := o.call(t, route.method, route.path, body, csrf, func(r *http.Request) {
				r.Header.Set("X-Tracebolt-Customer", customer)
			})
			failure, _ := result["error"].(map[string]any)
			if response.StatusCode != http.StatusForbidden || failure["code"] != "operator_capability_required" {
				t.Fatal("customer metadata changed named authority", phase, route.method, route.path, response.StatusCode)
			}
		}
	}
	check("before")
	// Shared and named startup modes are mutually exclusive. The preceding
	// public-HTTP test covers the real shared mutation; here the same production
	// store writes model already-retained organizational metadata under named mode.
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Same label is not a grant", 0, func() error { return nil }); err != nil {
		t.Fatal("fixture customer write failed")
	}
	assignment := store.CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: id, Identity: devices[id].identity}
	if err = o.app.store.CreateCustomerWindowsAssignment(context.Background(), assignment, func() error { return nil }); err != nil {
		t.Fatal("fixture assignment write failed")
	}
	check("after")
	if len(o.registry.List()) != 0 || o.app.aiConfigured() {
		t.Fatal("denied organization requests created trust or a provider")
	}
	if response, _ := o.call(t, http.MethodPost, "/api/auth/logout", map[string]any{}, csrf, nil); response.StatusCode != http.StatusOK {
		t.Fatal("fixture logout failed")
	}
	for _, route := range denied {
		if response, _ := o.call(t, route.method, route.path, map[string]any{"customerId": customer}, csrf, nil); response.StatusCode != http.StatusUnauthorized {
			t.Fatal("customer metadata admitted an anonymous request", route.method, route.path, response.StatusCode)
		}
	}
}
