package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
)

type servicePolicyLeaseFixture struct {
	*fixtureWindowsCapacitySource
	beforeLease func()
	onGuard     func(int)
	leases      int
}

func (f *servicePolicyLeaseFixture) WithWindowsIncidentAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	f.leases++
	if f.beforeLease != nil {
		f.beforeLease()
	}
	return f.fixtureWindowsCapacitySource.WithWindowsIncidentAuthority(ctx, in, func(authority func(time.Time) error) error {
		calls := 0
		return fn(func(at time.Time) error {
			calls++
			if f.onGuard != nil {
				f.onGuard(calls)
			}
			return authority(at)
		})
	})
}
func servicePolicyHandlerFixture(t *testing.T) (*operatorHandler, *servicePolicyLeaseFixture, operatorRequest, string) {
	h, _, op, _ := groupMaintenanceHandlerFixture(t)
	at := time.Now().UTC().Round(0)
	f := &servicePolicyLeaseFixture{fixtureWindowsCapacitySource: &fixtureWindowsCapacitySource{now: at, inputs: []windowscapacity.Input{capacityFixtureInput(at)}}}
	f.inputs[0].Services = windowsservicehealth.Sample{CollectedAt: at, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsmanaged.Service{{Name: "FixtureService", State: "running"}}}}
	m, err := newWindowsCapacityMonitor(h.app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	h.app.windowsCapacity = m
	return h, f, op, "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/policy"
}

// Recorder-only handler test. The https URL is synthetic request metadata;
// no TLS connection, socket, browser or native endpoint is involved.
func servicePolicyRequest(h *operatorHandler, op operatorRequest, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "https://maintenance.invalid"+path, strings.NewReader(string(raw)))
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	w := httptest.NewRecorder()
	h.windowsServiceAPI(w, r)
	return w
}
func TestWindowsServicePolicyAuthorityCommitGuards(t *testing.T) {
	for _, mode := range []string{"valid", "revoked", "replacement", "renewed-leaf", "expiry", "session", "rollback", "source-age"} {
		t.Run(mode, func(t *testing.T) {
			h, f, op, path := servicePolicyHandlerFixture(t)
			live := true
			op.active = func() bool { return live }
			at := f.now
			if mode == "source-age" {
				f.inputs[0].ReceivedAt = at.Add(-119 * time.Second)
				f.inputs[0].Services.CollectedAt = f.inputs[0].ReceivedAt
			}
			if mode == "revoked" || mode == "replacement" || mode == "renewed-leaf" {
				f.beforeLease = func() {
					switch mode {
					case "revoked":
						f.inputs[0].Authorized = false
					case "replacement":
						f.inputs[0].CertificateHash = strings.Repeat("e", 64)
					case "renewed-leaf":
						f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
					}
				}
			}
			f.onGuard = func(n int) {
				if n != 3 {
					return
				}
				switch mode {
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "session":
					live = false
				case "rollback":
					f.now = at.Add(-time.Second)
				case "source-age":
					f.now = at.Add(2 * time.Second)
				}
			}
			w := servicePolicyRequest(h, op, path, map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0})
			if f.leases != 1 {
				t.Fatal("ordinary save did not enter enrollment lease", f.leases)
			}
			states, err := h.app.store.WindowsServiceStates(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
				if w.Code != 200 || len(states) != 1 || !states[f.inputs[0].DeviceID].Policy.Enabled {
					t.Fatal(w.Code, w.Body.String())
				}
				return
			}
			if w.Code == 200 || len(states) != 0 {
				t.Fatal("failed authority guard committed", mode, w.Code, w.Body.String(), states)
			}
		})
	}
}
