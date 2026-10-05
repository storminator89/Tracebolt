package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceActionDefaultOffAndCapabilityGuards(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: namedDeviceID}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + namedDeviceID + "/service-actions"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous action read")
	}
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	csrf := login["csrfToken"].(string)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["configured"] != false || v["available"] != false || v["job"] != nil || v["preview"] != nil || v["reason"] != "not_configured" {
		t.Fatal("default enabled", r.StatusCode, v)
	}
	for _, test := range []struct {
		method, path, csrf string
		body               any
		modify             func(*http.Request)
		want               int
	}{{"POST", path + "/preview", csrf, map[string]string{"unit": "fixture.service"}, nil, 409}, {"POST", path + "/approve", csrf, map[string]string{"previewId": "x", "previewDigest": "x"}, nil, 409}, {"POST", path + "/preview", "bad", map[string]string{"unit": "fixture.service"}, nil, 403}, {"GET", path + "/approve", "", nil, nil, 405}, {"POST", path + "/anything", csrf, map[string]string{}, nil, 403}, {"GET", path + "?unit=fixture.service", "", nil, nil, 400}, {"POST", path + "/preview", csrf, map[string]string{}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403}} {
		r, _ = o.call(t, test.method, test.path, test.body, test.csrf, test.modify)
		if r.StatusCode != test.want {
			t.Fatalf("%s %s got%d want%d", test.method, test.path, r.StatusCode, test.want)
		}
	}
}
func TestSharedSessionCannotAuthorizeServiceAction(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, login := o.login(t)
	path := "/api/devices/" + namedDeviceID + "/service-actions/preview"
	if r, _ := o.call(t, "POST", path, map[string]string{"unit": "fixture.service"}, login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("shared session authorized action", r.StatusCode)
	}
}
func TestServiceActionExactMutationRoutesOnly(t *testing.T) {
	base := "/api/devices/" + namedDeviceID + "/service-actions"
	for _, path := range []string{base + "/approve/extra", base + "/preview/extra", base + "/other", base + "-extra/preview", base + "//approve"} {
		if _, _, ok := serviceActionRoute(httptest.NewRequest("POST", path, nil)); ok {
			t.Fatal("broad mutation route", path)
		}
	}
}

type clockActionFixture struct {
	record   actionjob.Record
	observed time.Time
}

func (f *clockActionFixture) ViewAt(context.Context, string) (actionjob.Record, time.Time, error) {
	return f.record, f.observed, nil
}
func (f *clockActionFixture) Preview(context.Context, string, string, string) (actionjob.Record, error) {
	return f.record, nil
}
func (f *clockActionFixture) Approve(context.Context, string, string, string, string) (actionjob.Record, error) {
	return f.record, nil
}
func (f *clockActionFixture) TransportProfile() string { return actionhelper.ProductionTLS }
func (f *clockActionFixture) Available() bool          { return true }
func actionAPIRecord(t *testing.T) (actionjob.Record, func(actionpermit.Permit) ([]byte, error), time.Time) {
	t.Helper()
	at := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("q", 32)))
	r, e := actionjob.New("manager_"+strings.Repeat("1", 32), namedDeviceID, actionpermit.Digest([]byte("incarnation")), key.Public().(ed25519.PublicKey), at)
	if e != nil {
		t.Fatal(e)
	}
	c := actionhelper.Capabilities{Version: actionhelper.CapabilitiesVersion, Enabled: true, ManagerID: r.ManagerID, KeyID: actionpermit.Digest(r.PublicKey), EndpointID: r.DeviceID, IncarnationDigest: r.IncarnationDigest, RootPolicyDigest: actionpermit.Digest([]byte("policy")), TransportProfile: actionhelper.ProductionTLS, CapturedAt: at.Unix(), MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: actionpermit.Digest([]byte("unit"))}}}
	if e = r.Report(c, at); e != nil {
		t.Fatal(e)
	}
	if _, e = r.MakePreview("action_"+strings.Repeat("2", 32), namedActorID, "fixture.service", actionhelper.ProductionTLS, at); e != nil {
		t.Fatal(e)
	}
	return r, func(p actionpermit.Permit) ([]byte, error) {
		b, e := actionpermit.SigningMessage(p)
		if e != nil {
			return nil, e
		}
		return actionpermit.Encode(p, ed25519.Sign(key, b))
	}, at
}
func TestServiceActionAPIUsesDurablyObservedTimeAcrossDeadline(t *testing.T) {
	r, sign, at := actionAPIRecord(t)
	p := *r.Preview
	j, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), sign)
	if e != nil {
		t.Fatal(e)
	}
	o, _ := namedOperatorFixture(t)
	clock := &clockActionFixture{record: r, observed: j.Deadline().Add(-time.Millisecond)}
	o.server.Config.Handler.(*operatorHandler).actions = clock
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	_ = login
	res, view := o.call(t, "GET", "/api/devices/"+namedDeviceID+"/service-actions", nil, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	job := view["job"].(map[string]any)
	if job["state"] != actionjob.Approved || view["serverNow"] != clock.observed.Format(time.RFC3339Nano) {
		t.Fatal("resampled later clock exposed uncommitted expiry", view)
	}
	clock.observed = j.Deadline()
	clock.record.ObserveExpiry(clock.observed)
	_, view = o.call(t, "GET", "/api/devices/"+namedDeviceID+"/service-actions", nil, "", nil)
	if view["job"].(map[string]any)["state"] != "expired" || clock.record.ClockFloor.Before(j.Deadline()) {
		t.Fatal("committed expiry not shown")
	}
}
func TestServiceActionChangedCapabilitiesSuppressObsoletePreview(t *testing.T) {
	for _, which := range []string{"changed", "removed", "root", "disabled", "stale"} {
		t.Run(which, func(t *testing.T) {
			r, _, at := actionAPIRecord(t)
			p := *r.Preview
			now := at.Add(time.Second)
			switch which {
			case "changed":
				r.Capabilities.Services[0].UnitPolicyDigest = actionpermit.Digest([]byte("changed"))
			case "removed":
				r.Capabilities.Services[0].Unit = "other.service"
			case "root":
				r.Capabilities.RootPolicyDigest = actionpermit.Digest([]byte("changed root"))
			case "disabled":
				r.Capabilities.Enabled = false
			case "stale":
				now = at.Add(time.Minute)
			}
			if usableServicePreview(r, actionhelper.ProductionTLS, now) != nil {
				t.Fatal("obsolete preview emitted")
			}
			if which == "changed" || which == "removed" || which == "root" {
				next, e := r.MakePreview("action_"+strings.Repeat("9", 32), p.ActorID, r.Capabilities.Services[0].Unit, actionhelper.ProductionTLS, now)
				if e != nil || next.Digest == p.Digest {
					t.Fatal("replacement preview blocked", e)
				}
			}
			encoded, _ := json.Marshal(r.Preview)
			if len(encoded) == 0 {
				t.Fatal("fixture")
			}
		})
	}
}
