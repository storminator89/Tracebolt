package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/model"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestResourceHistoryDeltaCanonicalCursor(t *testing.T) {
	for _, query := range []string{"", "afterSequence=1", "afterSequence=9223372036854775807"} {
		if _, ok := resourceHistoryAfter(&url.URL{RawQuery: query}); !ok {
			t.Fatal(query)
		}
	}
	for _, query := range []string{"afterSequence=0", "afterSequence=01", "afterSequence=-1", "afterSequence=+1", "afterSequence=1.0", "afterSequence=9223372036854775808", "afterSequence=%31", "afterSequence=1&afterSequence=2", "afterSequence=1&x=2", "x=1"} {
		if _, ok := resourceHistoryAfter(&url.URL{RawQuery: query}); ok {
			t.Fatal("accepted", query)
		}
	}
	if _, ok := resourceHistoryAfter(&url.URL{ForceQuery: true}); ok {
		t.Fatal("empty query accepted")
	}
}
func resourceDeltaFixture() enrollmentstore.ResourceHistoryView {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	v := enrollmentstore.EmptyResourceHistory(namedDeviceID, now, "available")
	for i, seq := range []string{"1", "3", "5"} {
		at := now.Add(time.Duration(i-2) * time.Minute)
		value := float64(i * 10)
		m := enrollmentstore.ResourceMetric{Value: &value, Quality: "healthy", CollectedAt: at}
		v.Points = append(v.Points, enrollmentstore.ResourcePoint{Sequence: seq, CollectedAt: at, ReceivedAt: at, CPU: m, Memory: m, Disk: m})
	}
	return v
}
func TestResourceHistoryDeltaPreservesAllNewRowsAndMetadata(t *testing.T) {
	v := resourceDeltaFixture()
	raw, e := encodeResourceHistoryFixture(v, "1")
	if e != nil {
		t.Fatal(e)
	}
	var d resourceHistoryDelta
	if e = json.Unmarshal(raw, &d); e != nil {
		t.Fatal(e)
	}
	if d.SchemaVersion != "tracebolt.resource-history-delta.v1" || d.BaseSequence != "1" || d.LastSequence != "5" || d.PointCount != 3 || !reflect.DeepEqual(d.Points, v.Points[1:]) || !d.ServerNow.Equal(v.ServerNow) || !d.WindowStart.Equal(v.WindowStart) {
		t.Fatal("changed history semantics")
	}
	if len(v.Points) != 3 || v.SchemaVersion != "tracebolt.resource-history.v1" {
		t.Fatal("mutated verified view")
	}
	raw, e = encodeResourceHistoryFixture(v, "5")
	if e != nil {
		t.Fatal(e)
	}
	d = resourceHistoryDelta{}
	if e = json.Unmarshal(raw, &d); e != nil || len(d.Points) != 0 || d.Points == nil || d.PointCount != 3 || d.LastSequence != "5" {
		t.Fatal("unchanged history resent", e)
	}
}
func TestResourceHistoryDeltaBootstrapFutureAndTerminalAreFull(t *testing.T) {
	for _, tc := range []struct{ after, status string }{{"", "available"}, {"9", "available"}, {"5", "revoked"}, {"5", "expired"}, {"5", "awaiting"}, {"5", "not_configured"}} {
		v := resourceDeltaFixture()
		v.Status = tc.status
		if tc.status != "available" {
			v.Points = []enrollmentstore.ResourcePoint{}
		}
		raw, e := encodeResourceHistoryFixture(v, tc.after)
		if e != nil {
			t.Fatal(e)
		}
		var out map[string]any
		if e = json.Unmarshal(raw, &out); e != nil || out["schemaVersion"] != "tracebolt.resource-history.v1" || out["baseSequence"] != nil {
			t.Fatal(tc, e)
		}
	}
}

func encodeResourceHistoryFixture(v enrollmentstore.ResourceHistoryView, after string) ([]byte, error) {
	value, e := resourceHistoryPayload(v, after)
	if e != nil {
		return nil, e
	}
	return json.Marshal(value)
}

func TestResourceHistoryDeltaOuterOperatorAdmission(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := namedDeviceID
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/resource-history"
	if r, _ := o.call(t, "GET", path+"?afterSequence=1", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous delta", r.StatusCode)
	}
	o.login(t)
	if r, v := o.call(t, "GET", path+"?afterSequence=1", nil, "", nil); r.StatusCode != 200 || v["status"] != "not_configured" || v["schemaVersion"] != "tracebolt.resource-history.v1" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("outer router rejected canonical delta or changed terminal response", r.StatusCode, v)
	}
	for _, suffix := range []string{"?afterSequence=0", "?afterSequence=01", "?afterSequence=1&afterSequence=2", "?afterSequence=9223372036854775808", "?range=1"} {
		if r, _ := o.call(t, "GET", path+suffix, nil, "", nil); r.StatusCode != 400 {
			t.Fatal("noncanonical cursor accepted", suffix, r.StatusCode)
		}
	}
	if r, _ := o.call(t, "GET", "/api/devices?afterSequence=1", nil, "", nil); r.StatusCode != 400 {
		t.Fatal("query exception broadened", r.StatusCode)
	}
}

func TestResourceHistoryDeltaOutputChecksOmittedPointExpiry(t *testing.T) {
	view := resourceDeltaFixture()
	start := view.ServerNow
	view.Points[0].CollectedAt = view.WindowStart
	payload, e := resourceHistoryPayload(view, "5")
	if e != nil {
		t.Fatal(e)
	}
	h := operatorHandler{app: setup(t), enrollment: overviewServiceFixtureWithClock(t, "https://overview.invalid", func() time.Time { return start.Add(time.Nanosecond) })}
	r := httptest.NewRequest("GET", "/api/devices/"+namedDeviceID+"/resource-history?afterSequence=5", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: func() bool { return true }}))
	w := httptest.NewRecorder()
	h.writeResourceHistoryResponse(w, r, payload, view.ValidateAt)
	if w.Code != 409 || strings.Contains(w.Body.String(), "baseSequence") {
		t.Fatal("omitted expired point escaped source recheck", w.Code)
	}
}
