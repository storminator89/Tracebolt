package api

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFleetEndpointIdentityOperatorGuards(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	path := "/api/fleet/endpoint-identities"
	response, _ := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 401 {
		t.Fatal("anonymous fleet metadata exposed")
	}
	o.login(t)
	response, value := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || value["schemaVersion"] != "tracebolt.fleet-endpoint-identity.v1" || len(value["items"].([]any)) != 0 {
		t.Fatal("manual-profile no-data response", response.StatusCode, value)
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "?device=host", nil, 400}, {"GET", path + "?", nil, 400},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		response, _ = o.call(t, tc.method, tc.path, nil, "", tc.change)
		if response.StatusCode != tc.want {
			t.Fatalf("fleet guard %s %s got %d", tc.method, tc.path, response.StatusCode)
		}
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable fleet metadata")
	}
}

func TestFleetEndpointIdentityFinalOutputRechecksAuthorityAndSession(t *testing.T) {
	for _, boundary := range []string{"success", "expiry", "logout", "cancel"} {
		t.Run(boundary, func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Second)
			checked := at
			calls := 0
			now := func() time.Time { calls++; return checked }
			service := overviewServiceFixtureWithClock(t, "https://overview.invalid", now)
			identity := inventoryIdentityClockFixture(t, service, at, true)
			calls = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			activeChecks := 0
			r := httptest.NewRequest("GET", "/api/fleet/endpoint-identities", nil)
			r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool {
				activeChecks++
				if boundary == "expiry" {
					checked = time.Unix(identity.Intent.NotAfter, 0).UTC()
				}
				if boundary == "cancel" {
					cancel()
				}
				return boundary != "logout"
			}}))
			h := operatorHandler{app: setup(t), enrollment: service}
			w := httptest.NewRecorder()
			h.fleetEndpointIdentity(w, r)
			if boundary == "logout" || boundary == "cancel" {
				if w.Code != 401 || strings.Contains(w.Body.String(), identity.Approval.DeviceID) {
					t.Fatal("invalidated fleet read exposed data", w.Code)
				}
				return
			}
			var view enrollmentstore.FleetEndpointIdentityView
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Items) != 1 || activeChecks != 3 || calls != 5 {
				t.Fatal("fleet output boundary checks", w.Code, activeChecks, calls)
			}
			want := "not_collected"
			if boundary == "expiry" {
				want = "expired"
			}
			if view.Items[0].Status != want || view.Items[0].DeviceID != identity.Approval.DeviceID || !view.ServerNow.Equal(checked) || view.Items[0].Latest != nil {
				t.Fatal("fleet authority not rechecked")
			}
		})
	}
}

func TestFleetEndpointIdentityPostEncodeExpirySessionAndExactBytes(t *testing.T) {
	for _, crossing := range []string{"encoding_expiry", "session_expiry", "encoding_revoked", "clock_revoked", "encoding_cancel", "clock_cancel", "success"} {
		t.Run(crossing, func(t *testing.T) {
			start := time.Now().UTC().Truncate(time.Second)
			checked := start
			var active atomic.Bool
			active.Store(true)
			var encodes atomic.Int64
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := func() time.Time {
				if encodes.Load() > 0 && crossing == "clock_revoked" {
					active.Store(false)
				}
				if encodes.Load() > 0 && crossing == "clock_cancel" {
					cancel()
				}
				return checked
			}
			service := overviewServiceFixtureWithClock(t, "https://overview.invalid", now)
			identity := inventoryIdentityClockFixture(t, service, start, true)
			view, err := service.FleetEndpointIdentityView(ctx, start)
			if err != nil || len(view.Items) != 1 {
				t.Fatal("real fleet read fixture", err)
			}
			expiry := time.Unix(identity.Intent.NotAfter, 0).UTC()
			h := operatorHandler{app: setup(t), enrollment: service}
			r := httptest.NewRequest("GET", "/api/fleet/endpoint-identities", nil)
			r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool {
				if crossing == "session_expiry" {
					checked = expiry
				}
				return active.Load()
			}}))
			value := overviewEncodingBoundaryFixture{calls: &encodes, payload: "private-synthetic-fleet-output", afterEncode: func() {
				if crossing == "encoding_expiry" {
					checked = expiry
				}
				if crossing == "encoding_revoked" {
					active.Store(false)
				}
				if crossing == "encoding_cancel" {
					cancel()
				}
			}}
			w := httptest.NewRecorder()
			h.writeFleetEndpointIdentityResponse(w, r, value, view.ValidateAt)
			if encodes.Load() != 1 {
				t.Fatal("fleet encoded more than once")
			}
			if crossing == "success" {
				expected := []byte("{\"fixture\":\"private-synthetic-fleet-output\"}\n")
				if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), expected) {
					t.Fatal("output differs from exact checked bytes", w.Code)
				}
				return
			}
			want := 401
			if crossing == "encoding_expiry" || crossing == "session_expiry" {
				want = 409
			}
			if w.Code != want || bytes.Contains(w.Body.Bytes(), []byte(value.payload)) {
				t.Fatal("expired or revoked encoded fleet data escaped", w.Code)
			}
		})
	}
}

func TestFleetEndpointIdentityResponseCapIncludesNewline(t *testing.T) {
	h := operatorHandler{app: setup(t)}
	for _, size := range []int{fleetEndpointIdentityResponseBytes - 4, fleetEndpointIdentityResponseBytes - 3} {
		r := httptest.NewRequest("GET", "/api/fleet/endpoint-identities", nil)
		r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: func() bool { return true }}))
		w := httptest.NewRecorder()
		h.writeFleetEndpointIdentityResponse(w, r, strings.Repeat("x", size), nil)
		if size == fleetEndpointIdentityResponseBytes-4 {
			if w.Code != 200 || w.Body.Len() != fleetEndpointIdentityResponseBytes-1 {
				t.Fatal("bounded exact-byte response", w.Code, w.Body.Len())
			}
		} else if w.Code != 503 || strings.Contains(w.Body.String(), strings.Repeat("x", 32)) {
			t.Fatal("wire ceiling accepted", w.Code, w.Body.Len())
		}
	}
}
