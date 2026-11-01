package api

import (
	"localrmm/internal/operatorauth"
	"net/http"
	"testing"
)

// This is the TB-06 inventory/denial slice, not a named-administration grant.
// Keep these direct requests behind the real operator listener. The fixture has
// no enrollment authority, AI provider or customer source; authorization must
// reject the request before any unavailable feature or body parser handles it.
type namedAdministrationRoute struct {
	method string
	path   string
}

func namedAdministrationDeniedRoutes() []namedAdministrationRoute {
	invite := "invite_0123456789abcdef0123456789abcdef"
	customer := "customer_0123456789abcdef0123456789abcdef"
	routes := []namedAdministrationRoute{
		{http.MethodPost, "/api/lan/agents/approve"},
		{http.MethodPost, "/api/lan/agents/" + namedDeviceID + "/revoke"},
		{http.MethodGet, "/api/customers"},
		{http.MethodPost, "/api/customers"},
		{http.MethodPost, "/api/customers/" + customer},
		{http.MethodGet, "/api/customer-windows-assignments"},
		{http.MethodPost, "/api/customer-windows-assignments"},
		{http.MethodPost, "/api/ai/config"},
		{http.MethodPost, "/api/ai/config/persistent"},
		{http.MethodPost, "/api/ai/config/lan"},
		{http.MethodPost, "/api/ai/config/lan-private-ca"},
		{http.MethodPost, "/api/ai/config/clear"},
		{http.MethodPost, "/api/ai/test"},
		{http.MethodPost, "/api/cases/case-demo-win-01-service/analyze"},
		{http.MethodPost, "/api/ai/proactive"},
		{http.MethodPost, "/api/ai/journal"},
		{http.MethodPost, "/api/ai/network-review/preview"},
		{http.MethodPost, "/api/ai/network-review/run"},
	}
	for _, domain := range []string{"/api/enrollment", "/api/windows/enrollment", "/api/macos/enrollment", "/api/macos-inventory/enrollment"} {
		for _, suffix := range []string{"/invitations", "/automatic-bootstrap", "/" + invite + "/approve", "/" + invite + "/disable-renewal", "/" + invite + "/terminate"} {
			routes = append(routes, namedAdministrationRoute{http.MethodPost, domain + suffix})
		}
	}
	return routes
}

// Even every currently defined grant together is not an ambient administrator.
// Separate principals are deliberate: a successful login's actual actor must be
// server-derived, but neither identity nor a maintenance grant widens routes.
func TestNamedAdministrationContractDenials(t *testing.T) {
	all := []operatorauth.Capability{
		operatorauth.Read, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates,
		operatorauth.RestartService, operatorauth.ManageAlarms, operatorauth.ManageApplicationChecks,
		operatorauth.WindowsServiceControl, operatorauth.WindowsUpdateInstall, operatorauth.WindowsUpdateDownload,
		operatorauth.WindowsUpdateSchedule, operatorauth.WindowsSoftwareInstall,
		operatorauth.WindowsManagedMSIDeliver, operatorauth.WindowsManagedMSIInstall, operatorauth.WindowsManagedMSISchedule,
		operatorauth.ManageSessions,
	}
	operators := []operatorauth.Operator{
		{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}},
		{ID: "operator_11111111111111111111111111111111", Username: "maintainer-a", PasswordHash: testOperatorHash(), Capabilities: all},
		{ID: "operator_22222222222222222222222222222222", Username: "maintainer-b", PasswordHash: testOperatorHash(), Capabilities: all},
	}
	o := newOperatorFixture(t, 0)
	auth, err := operatorauth.New(operatorauth.Config{Operators: operators})
	if err != nil {
		t.Fatal("named contract fixture rejected", err)
	}
	o.server.Config.Handler.(*operatorHandler).auth = auth
	for _, account := range operators {
		t.Run(account.Username, func(t *testing.T) {
			response, session := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": account.Username, "password": operatorFixturePassword}, "", nil)
			if response.StatusCode != http.StatusOK || session["actorId"] != account.ID {
				t.Fatal("login did not bind the actual configured actor", response.StatusCode)
			}
			capabilities, ok := session["capabilities"].([]any)
			if !ok || len(capabilities) != len(account.Capabilities) {
				t.Fatal("login did not retain every explicitly configured grant")
			}
			configured := make(map[operatorauth.Capability]bool, len(account.Capabilities))
			for _, capability := range account.Capabilities {
				configured[capability] = true
			}
			canManageAll := configured[operatorauth.ManageSessions]
			for _, capability := range capabilities {
				name, ok := capability.(string)
				if !ok || !configured[operatorauth.Capability(name)] {
					t.Fatal("login displayed unconfigured or duplicate authority")
				}
				delete(configured, operatorauth.Capability(name))
			}
			csrf := session["csrfToken"].(string)
			for _, route := range namedAdministrationDeniedRoutes() {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					// Supplied authority is deliberately invalid. Denial must come
					// from server-held route authority, not body validation or UI.
					body := map[string]any{"actorId": operators[1].ID, "capabilities": []string{"admin"}}
					if route.method == http.MethodGet {
						body = nil
					}
					response, result := o.call(t, route.method, route.path, body, csrf, nil)
					failure, _ := result["error"].(map[string]any)
					if response.StatusCode != http.StatusForbidden || failure["code"] != "operator_capability_required" {
						t.Fatal("direct route did not deny missing administrative authority", response.StatusCode, result)
					}
				})
			}
			// Session lifecycle is a deliberate exception to the legacy-write
			// denial: read accounts can revoke their own account's sessions, and
			// only an explicit manage_sessions grant permits cross-account scope.
			response, view := o.call(t, http.MethodGet, "/api/auth/sessions", nil, "", nil)
			items, ok := view["items"].([]any)
			if response.StatusCode != http.StatusOK || !ok || len(items) != 1 || view["canManageAll"] != canManageAll {
				t.Fatal("session-grant exception did not retain its exact scope", response.StatusCode, view)
			}
			item, ok := items[0].(map[string]any)
			if !ok || item["actorId"] != account.ID || item["current"] != true {
				t.Fatal("session view did not bind the actual current actor")
			}
			if response, result := o.call(t, http.MethodPost, "/api/auth/sessions/revoke", map[string]any{"sessionId": item["id"]}, csrf, nil); response.StatusCode != http.StatusOK || result["revoked"] != true {
				t.Fatal("named account could not revoke its current session", response.StatusCode)
			}
			if response, _ := o.call(t, http.MethodGet, "/api/devices", nil, "", nil); response.StatusCode != http.StatusUnauthorized {
				t.Fatal("revoked contract fixture retained read access", response.StatusCode)
			}
		})
	}
	if len(o.registry.List()) != 0 || o.app.aiConfigured() {
		t.Fatal("denied routes created trust or configured a provider")
	}
}

func TestNamedAdministrationContractAnonymousDenials(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	for _, route := range namedAdministrationDeniedRoutes() {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response, result := o.call(t, route.method, route.path, map[string]any{}, "", nil)
			failure, _ := result["error"].(map[string]any)
			if response.StatusCode != http.StatusUnauthorized || failure["code"] != "authentication_required" {
				t.Fatal("anonymous direct route reached administrative handling", response.StatusCode, result)
			}
		})
	}
}

func TestNamedAdministrationContractReadsRemainDistinct(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, session := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	for _, path := range []string{"/api/enrollment", "/api/windows/enrollment", "/api/macos/enrollment", "/api/macos-inventory/enrollment", "/api/lan/agents", "/api/ai/config", "/api/devices"} {
		t.Run(http.MethodGet+" "+path, func(t *testing.T) {
			if response, _ := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode != http.StatusOK {
				t.Fatal("existing read was lost", response.StatusCode)
			}
		})
	}
	// These are reads, but a missing complete-profile source must remain explicit.
	for _, path := range []string{"/api/ai/proactive", "/api/ai/journal", "/api/ai/journal/source/" + namedDeviceID, "/api/ai/journal/" + namedDeviceID + "/incident-fixture"} {
		if response, _ := o.call(t, http.MethodGet, path, nil, "", nil); response.StatusCode != http.StatusConflict {
			t.Fatal("read did not reach its feature availability guard", path, response.StatusCode)
		}
	}
	// The broad GET/HEAD classifier is not an implementation of HEAD on APIs.
	if response, _ := o.call(t, http.MethodHead, "/api/ai/config", nil, "", nil); response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("matrix incorrectly promoted HEAD to a supported API method", response.StatusCode)
	}
	if response, _ := o.call(t, http.MethodPost, "/api/auth/logout", map[string]any{}, session["csrfToken"].(string), nil); response.StatusCode != http.StatusOK {
		t.Fatal("read fixture logout failed")
	}
}
