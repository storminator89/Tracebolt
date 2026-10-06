package api

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type investigationsSource struct {
	missingDeadline bool
	now             time.Time
	inputs          []health.Input
	calls           int
	change          func(int)
	err             error
}

func (s *investigationsSource) Now() time.Time { return s.now }
func (s *investigationsSource) HealthInputs(context.Context, map[string][]string, time.Time) ([]health.Input, error) {
	s.calls++
	if s.change != nil {
		s.change(s.calls)
	}
	for i := range s.inputs {
		if !s.missingDeadline && s.inputs[i].AuthorityUntil.IsZero() {
			s.inputs[i].AuthorityUntil = s.now.Add(time.Hour)
		}
	}
	return s.inputs, s.err
}
func investigationDevice(n int) string { return fmt.Sprintf("agent_%032x", n) }
func investigationsFixture(t *testing.T) (operatorFixture, *investigationsSource) {
	t.Helper()
	o := newOperatorFixture(t, time.Hour)
	source := &investigationsSource{now: time.Now().UTC().Truncate(time.Second), inputs: []health.Input{{DeviceID: investigationDevice(1), Authorized: true}}}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	return o, source
}
func TestInvestigationsReadsRealDurableTransitionsWithoutMutation(t *testing.T) {
	o, source := investigationsFixture(t)
	ctx := context.Background()
	id := source.inputs[0].DeviceID
	_, _ = o.login(t)
	at := source.now.Add(-10 * time.Minute)
	value := 95.0
	for i := 0; i <= 4; i++ {
		when := at.Add(time.Duration(i) * 30 * time.Second)
		_, err := o.app.store.EvaluateHealth(ctx, health.Input{DeviceID: id, Authorized: true, ReceivedAt: when, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: when}}, when)
		if err != nil {
			t.Fatal(err)
		}
	}
	source.now = at.Add(2 * time.Minute)
	before, err := o.app.store.HealthStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, view := o.call(t, "GET", "/api/investigations", nil, "", nil)
	if r.StatusCode != 200 || view["counts"].(map[string]any)["open"] != float64(1) {
		t.Fatal(r.StatusCode, view)
	}
	item := view["items"].([]any)[0].(map[string]any)
	incident := item["incident"].(map[string]any)
	if item["deviceId"] != id || incident["kind"] != "filesystem" || incident["id"] != before[id].Incidents[0].ID {
		t.Fatal("not the durable incident", item)
	}
	after, _ := o.app.store.HealthStates(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET changed durable health state")
	}
	// Acknowledgement is retained separately and does not resolve or hide it.
	_, err = o.app.store.UpdateHealth(ctx, id, func(s *health.State) error { return s.Acknowledge(s.Incidents[0].ID, source.now) })
	if err != nil {
		t.Fatal(err)
	}
	_, view = o.call(t, "GET", "/api/investigations", nil, "", nil)
	if view["counts"].(map[string]any)["open"] != float64(1) || view["items"].([]any)[0].(map[string]any)["incident"].(map[string]any)["acknowledgedAt"] == nil {
		t.Fatal("acknowledgement resolved incident")
	}
	// Advancing fresh observations satisfy the existing evaluator's recovery rule.
	value = 80
	for i := 5; i <= 7; i++ {
		when := at.Add(time.Duration(i) * 30 * time.Second)
		_, err = o.app.store.EvaluateHealth(ctx, health.Input{DeviceID: id, Authorized: true, ReceivedAt: when, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: when}}, when)
		if err != nil {
			t.Fatal(err)
		}
		source.now = when
	}
	_, view = o.call(t, "GET", "/api/investigations?scope=recovered&offset=0", nil, "", nil)
	counts := view["counts"].(map[string]any)
	if counts["open"] != float64(0) || counts["recovered"] != float64(1) || len(view["items"].([]any)) != 1 {
		t.Fatal(view)
	}
	// A stopped service closes its incident but never becomes a recovered case.
	_, err = o.app.store.UpdateHealth(ctx, id, func(s *health.State) error {
		if err := s.SetServices([]string{"sample.service"}, source.now); err != nil {
			return err
		}
		s.NextID++
		s.Incidents = append(s.Incidents, health.Incident{ID: fmt.Sprintf("health_%016x", s.NextID), Key: "service:sample.service", Kind: "service", Target: "sample.service", OpenedAt: source.now, LastObservedAt: source.now})
		return s.SetServices([]string{}, source.now)
	})
	if err != nil {
		t.Fatal(err)
	}
	_, view = o.call(t, "GET", "/api/investigations?scope=closed", nil, "", nil)
	if view["counts"].(map[string]any)["closed"] != float64(1) || view["items"].([]any)[0].(map[string]any)["incident"].(map[string]any)["closedReason"] != "monitoring_stopped" {
		t.Fatal(view)
	}
}
func TestInvestigationsAuthorityErrorsAndReadOnlyBoundary(t *testing.T) {
	o, source := investigationsFixture(t)
	if r, _ := o.call(t, "GET", "/api/investigations", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read")
	}
	_, session := o.login(t)
	for _, path := range []string{"/api/investigations?scope=invalid", "/api/investigations?offset=-1", "/api/investigations?offset=1", "/api/investigations?offset=00", "/api/investigations?offset=2550", "/api/investigations?scope=open&scope=all", "/api/investigations?secret=x", "/api/investigations?offset=%XX"} {
		if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 400 {
			t.Fatal(path, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "POST", "/api/investigations", map[string]any{}, session["csrfToken"].(string), nil); r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("write method accepted", r.StatusCode)
	}
	source.inputs[0].Authorized = false
	_, view := o.call(t, "GET", "/api/investigations", nil, "", nil)
	if len(view["devices"].([]any)) != 0 || len(view["items"].([]any)) != 0 {
		t.Fatal("revoked device included")
	}
	source.inputs[0].Authorized = true
	source.calls = 0
	source.change = func(call int) {
		if call == 2 {
			source.inputs[0].Authorized = false
		}
	}
	if r, _ := o.call(t, "GET", "/api/investigations", nil, "", nil); r.StatusCode != 409 {
		t.Fatal("revoked during read", r.StatusCode)
	}
	source.change = nil
	source.err = errors.New("fixture source failure")
	if r, _ := o.call(t, "GET", "/api/investigations", nil, "", nil); r.StatusCode == 200 {
		t.Fatal("failure became empty success")
	}
	source.err = nil
	source.inputs[0].Authorized = true
	source.calls = 0
	source.change = func(call int) {
		if call == 2 {
			source.now = source.now.Add(-time.Second)
		}
	}
	// Session invalidation also suppresses prepared bytes.
	source.change = func(call int) {
		if call == 2 {
			_, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, session["csrfToken"].(string), nil)
		}
	}
	if r, _ := o.call(t, "GET", "/api/investigations", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("revoked session returned bytes", r.StatusCode)
	}
}
func TestInvestigationsUnknownFreshnessAndBoundedPaging(t *testing.T) {
	o, source := investigationsFixture(t)
	_, _ = o.login(t)
	ctx := context.Background()
	at := source.now.Add(-5 * time.Minute)
	source.inputs = []health.Input{}
	for n := 1; n <= 25; n++ {
		id := investigationDevice(n)
		source.inputs = append(source.inputs, health.Input{DeviceID: id, Authorized: true})
		_, err := o.app.store.UpdateHealth(ctx, id, func(s *health.State) error {
			s.EvaluatedAt = &at
			s.Checks[0].State = "ok"
			s.Checks[0].ObservedAt = &at
			s.Checks[1].State = "open"
			s.Checks[1].ObservedAt = &at
			value := 95.0
			s.Checks[1].Value = &value
			for i := 1; i <= 100; i++ {
				s.NextID++
				x := health.Incident{ID: fmt.Sprintf("health_%016x", s.NextID), Key: "filesystem:root", Kind: "filesystem", Target: "/", OpenedAt: at, LastObservedAt: at}
				if i < 100 {
					x.ResolvedAt = &at
					x.ClosedReason = "recovered"
				}
				s.Incidents = append(s.Incidents, x)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	r, view := o.call(t, "GET", "/api/investigations?scope=all&offset=50", nil, "", nil)
	if r.StatusCode != 200 || view["total"] != float64(2500) || len(view["items"].([]any)) != 50 || view["counts"].(map[string]any)["open"] != float64(25) {
		t.Fatal(r.StatusCode, view["total"])
	}
	for _, raw := range view["devices"].([]any) {
		device := raw.(map[string]any)
		if device["status"] != "unknown" || len(device["incidents"].([]any)) != 0 {
			t.Fatal("current health invented or history repeated")
		}
		for _, v := range device["checks"].([]any) {
			c := v.(map[string]any)
			if c["state"] != "unknown" || c["value"] != nil {
				t.Fatal("stale check value", c)
			}
		}
	}
	_, last := o.call(t, "GET", "/api/investigations?scope=all&offset=2450", nil, "", nil)
	if len(last["items"].([]any)) != 50 {
		t.Fatal("last page")
	}
	_, empty := o.call(t, "GET", "/api/investigations?scope=all&offset=2500", nil, "", nil)
	if len(empty["items"].([]any)) != 0 || empty["total"] != float64(2500) {
		t.Fatal("past-end page")
	}
	source.inputs = append(source.inputs, health.Input{DeviceID: "agent_" + strings.Repeat("f", 32), Authorized: true})
	if r, _ := o.call(t, "GET", "/api/investigations", nil, "", nil); r.StatusCode != 503 {
		t.Fatal("unbounded fleet")
	}
}
func TestInvestigationsNamedReaderCanReadWithoutAdminGrant(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	source := &investigationsSource{now: time.Now().UTC(), inputs: []health.Input{{DeviceID: namedDeviceID, Authorized: true}}}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	r, view := o.call(t, "GET", "/api/investigations", nil, "", nil)
	if r.StatusCode != 200 || len(view["devices"].([]any)) != 1 {
		t.Fatal(r.StatusCode, view)
	}
	if view["devices"].([]any)[0].(map[string]any)["status"] != "unknown" {
		t.Fatal("unevaluated device became healthy")
	}
}

func TestInvestigationsSecondReadExpiryAndClockBoundary(t *testing.T) {
	for _, mode := range []string{"expiry", "slow", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, _ = o.login(t)
			source.inputs[0].AuthorityUntil = source.now.Add(time.Second)
			source.change = func(call int) {
				if call == 2 {
					switch mode {
					case "expiry":
						source.now = source.now.Add(time.Second)
					case "slow":
						source.now = source.now.Add(6 * time.Second)
					case "rollback":
						source.now = source.now.Add(-time.Second)
					}
				}
			}
			r, view := o.call(t, "GET", "/api/investigations?scope=open&offset=0", nil, "", nil)
			if r.StatusCode == 200 || view["items"] != nil || view["devices"] != nil {
				t.Fatal("expired or temporally untrusted read disclosed data", r.StatusCode)
			}
		})
	}
}
func TestInvestigationsQueryExceptionDoesNotChangeOtherRoutes(t *testing.T) {
	o, _ := investigationsFixture(t)
	_, _ = o.login(t)
	for _, path := range []string{"/api/overview?scope=open", "/api/devices?offset=0", "/api/investigations/extra?scope=open", "/api/investigations?", "/api/%69nvestigations?scope=open"} {
		if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 400 {
			t.Fatal(path, r.StatusCode)
		}
	}
}

func TestInvestigationsMissingAuthorityDeadlineFailsClosed(t *testing.T) {
	o, source := investigationsFixture(t)
	_, _ = o.login(t)
	source.missingDeadline = true
	r, view := o.call(t, "GET", "/api/investigations", nil, "", nil)
	if r.StatusCode != 409 || view["items"] != nil {
		t.Fatal("missing deadline disclosed history", r.StatusCode)
	}
}

// The loopback browser's manual awaiting-agent fixture calls api.New without a
// managed enrollment/Health monitor. Exercise that same real operator handler
// boundary: lack of assessment is an error, not an empty successful history.
func TestInvestigationsUnavailableWithoutHealthMonitor(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	if o.app.health != nil {
		t.Fatal("fixture unexpectedly configured Health")
	}
	if r, _ := o.call(t, "GET", "/api/investigations?scope=open&offset=0", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous investigation read", r.StatusCode)
	}
	_, _ = o.login(t)
	r, body := o.call(t, "GET", "/api/investigations?scope=open&offset=0", nil, "", nil)
	if r.StatusCode != 409 {
		t.Fatal("missing Health monitor became success", r.StatusCode)
	}
	failure, ok := body["error"].(map[string]any)
	if !ok || failure["code"] != "health_unavailable" {
		t.Fatal("wrong unavailable contract", body)
	}
	for _, field := range []string{"items", "devices", "counts", "total"} {
		if _, ok := body[field]; ok {
			t.Fatal("unavailable response contained assessment data", field)
		}
	}
}
