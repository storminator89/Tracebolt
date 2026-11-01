package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

func customerReadOperators() []operatorauth.Operator {
	all := []operatorauth.Capability{operatorauth.Read, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates, operatorauth.RestartService, operatorauth.ManageAlarms, operatorauth.ManageApplicationChecks, operatorauth.WindowsServiceControl, operatorauth.WindowsUpdateInstall, operatorauth.WindowsUpdateSchedule, operatorauth.WindowsSoftwareInstall, operatorauth.WindowsManagedMSIDeliver, operatorauth.WindowsManagedMSIInstall, operatorauth.WindowsManagedMSISchedule, operatorauth.WindowsUpdateDownload, operatorauth.ManageSessions}
	return []operatorauth.Operator{
		{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}},
		{ID: "operator_11111111111111111111111111111111", Username: "maintainer", PasswordHash: testOperatorHash(), Capabilities: all},
		{ID: "operator_22222222222222222222222222222222", Username: "customer-reader-a", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ReadCustomers}},
		{ID: "operator_33333333333333333333333333333333", Username: "customer-reader-b", PasswordHash: testOperatorHash(), Capabilities: append(append([]operatorauth.Capability{}, all...), operatorauth.ReadCustomers)},
	}
}

func TestNamedCustomerReadRequiresExactGrantAndNeverWrites(t *testing.T) {
	o := newOperatorFixture(t, 0)
	operators := customerReadOperators()
	auth, err := operatorauth.New(operatorauth.Config{Operators: operators})
	if err != nil {
		t.Fatal(err)
	}
	h := o.server.Config.Handler.(*operatorHandler)
	h.auth = auth
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Private customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	id := source.inputs[0].DeviceID
	assignment := store.CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: id, Identity: devices[id].identity}
	if err = o.app.store.CreateCustomerWindowsAssignment(context.Background(), assignment, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	reads := []string{"/api/customers", "/api/customer-windows-assignments"}
	for _, path := range reads {
		if response, _ := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode != http.StatusUnauthorized {
			t.Fatal("anonymous customer read admitted", path, response.StatusCode)
		}
	}
	for index, account := range operators {
		t.Run(account.Username, func(t *testing.T) {
			response, session := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": account.Username, "password": operatorFixturePassword}, "", nil)
			if response.StatusCode != http.StatusOK || session["actorId"] != account.ID {
				t.Fatal("read did not start with the actual named actor", response.StatusCode)
			}
			csrf := session["csrfToken"].(string)
			for _, path := range reads {
				response, view := o.call(t, http.MethodGet, path, nil, "", nil)
				if index < 2 {
					raw, _ := json.Marshal(view)
					if response.StatusCode != http.StatusForbidden || strings.Contains(string(raw), "Private customer") || strings.Contains(string(raw), assignment.Identity) {
						t.Fatal("ordinary or unrelated grants disclosed customers", path, response.StatusCode)
					}
				} else {
					if response.StatusCode != http.StatusOK || view["customers"].([]any)[0].(map[string]any)["name"] != "Private customer" {
						t.Fatal("explicit customer read denied", path, response.StatusCode, view)
					}
					if path == reads[1] {
						row := view["devices"].([]any)[0].(map[string]any)
						if row["identity"] != assignment.Identity || row["customerId"] != customer {
							t.Fatal("read lost the original assignment binding", row)
						}
					}
				}
			}
			// Correct CSRF and forged caller authority must not turn read into
			// customer creation, renaming, assignment or any other mutation.
			for _, path := range append(append([]string{}, reads...), "/api/customers/"+customer) {
				for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
					body := map[string]any{"name": "Changed", "expectedRevision": 1, "customerId": customer, "deviceId": id, "identity": assignment.Identity, "acknowledged": true, "actorId": account.ID, "capabilities": []string{"admin", "read_customers"}}
					if response, _ := o.call(t, method, path, body, csrf, nil); response.StatusCode != http.StatusForbidden {
						t.Fatal("customer read acquired mutation authority", method, path, response.StatusCode)
					}
				}
			}
			if index >= 2 {
				if response, _ := o.call(t, http.MethodGet, "/api/customers/"+customer, nil, "", nil); response.StatusCode != http.StatusMethodNotAllowed {
					t.Fatal("customer read invented a detail route", response.StatusCode)
				}
				for _, path := range reads {
					if response, _ := o.call(t, http.MethodHead, path, nil, "", nil); response.StatusCode != http.StatusForbidden {
						t.Fatal("customer GET permission promoted HEAD", response.StatusCode)
					}
					if response, _ := o.call(t, http.MethodGet, path+"?authority=read_customers", nil, "", nil); response.StatusCode != http.StatusBadRequest {
						t.Fatal("customer grant bypassed canonical paths", response.StatusCode)
					}
				}
			}
			if response, _ := o.call(t, http.MethodPost, "/api/auth/logout", map[string]any{}, csrf, nil); response.StatusCode != http.StatusOK {
				t.Fatal("customer reader logout failed")
			}
			for _, path := range reads {
				if response, _ := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode != http.StatusUnauthorized {
					t.Fatal("revoked customer reader retained access", path, response.StatusCode)
				}
			}
		})
	}
	customers, err := o.app.store.Customers(context.Background(), manager)
	if err != nil || len(customers) != 1 || customers[0].Name != "Private customer" || customers[0].Revision != 1 {
		t.Fatal("denied writes changed customer records", customers, err)
	}
	assignments, err := o.app.store.CustomerWindowsAssignments(context.Background(), manager)
	if err != nil || len(assignments) != 1 || assignments[0] != assignment {
		t.Fatal("denied writes changed assignments", assignments, err)
	}
}

type customerReadRevokingSource struct {
	*fixtureMonitoringSource
	onBinding func()
}

func (s *customerReadRevokingSource) Binding() enrollmentstate.Binding {
	if s.onBinding != nil {
		s.onBinding()
	}
	return s.fixtureMonitoringSource.Binding()
}

func TestNamedCustomerReadRechecksRevocationAndIssuer(t *testing.T) {
	for _, path := range []string{"/api/customers", "/api/customer-windows-assignments"} {
		t.Run(path, func(t *testing.T) {
			o := newOperatorFixture(t, 0)
			account := customerReadOperators()[2]
			auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{account}})
			if err != nil {
				t.Fatal(err)
			}
			h := o.server.Config.Handler.(*operatorHandler)
			h.auth = auth
			source := &customerReadRevokingSource{fixtureMonitoringSource: &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}}
			h.fleetGroupSources = []fleetGroupSource{source}
			response, _ := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": account.Username, "password": operatorFixturePassword}, "", nil)
			if response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 {
				t.Fatal("customer reader login failed")
			}
			token := response.Cookies()[0].Value
			source.issuerEnd = source.now
			if response, _ := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode == http.StatusOK {
				t.Fatal("customer grant ignored issuer expiry")
			}
			source.issuerEnd = source.now.Add(time.Hour)
			bindingReads := 0
			source.onBinding = func() {
				bindingReads++
				if bindingReads == 3 {
					auth.Logout(token)
				}
			}
			if response, view := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode == http.StatusOK || view["customers"] != nil || view["devices"] != nil {
				t.Fatal("revocation during source reads disclosed a response", response.StatusCode)
			}
			if bindingReads < 3 {
				t.Fatal("read never reached the revocation guard")
			}
		})
	}
}
