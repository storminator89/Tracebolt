package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestJournalOperatorRealTLSGuardsAndUnavailable(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/journal"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous journal exposure")
	}
	o.login(t)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["configured"] != false || v["request"] != nil || v["expectedFloor"] != "0" || v["localStatus"] != "unknown" || v["contentStatus"] != "unavailable" {
		t.Fatal("unsafe unavailable view")
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "?search=secret", nil, 400}, {"GET", path + "/extra", nil, 404}, {"GET", path + "/create", nil, 405},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"POST", path + "/create", nil, 409},
	} {
		r, _ = o.call(t, tc.method, tc.path, nil, "", tc.change)
		if r.StatusCode != tc.want {
			t.Fatalf("guard got %d want %d", r.StatusCode, tc.want)
		}
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable response")
	}
}
func TestJournalUnavailableViewRechecksSession(t *testing.T) {
	app := setup(t)
	id := "agent_" + strings.Repeat("2", 32)
	var active atomic.Bool
	active.Store(true)
	app.mu.Lock()
	app.lanDevices = func() ([]model.Device, error) { active.Store(false); return []model.Device{{ID: id}}, nil }
	app.mu.Unlock()
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+id+"/journal", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	h.journal(w, r)
	if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.journal-view") {
		t.Fatal("stale session exposure")
	}
}
func TestJournalExplicitAcknowledgementsAndNestedContracts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	q := journalview.Query{Unit: "invented.service", Start: now.Add(-time.Minute), End: now, MaxPriority: 3}
	raw, _ := json.Marshal(q)
	base := `{"expectedFloor":"0","query":` + string(raw) + `,"acknowledgeLogContent":true,"acknowledgePlaintext":false}`
	for _, tc := range []struct {
		name, body         string
		plaintext, success bool
	}{
		{"TLS explicit", base, false, true}, {"HTTP needs separate ack", base, true, false}, {"HTTP explicit", strings.Replace(base, `"acknowledgePlaintext":false`, `"acknowledgePlaintext":true`, 1), true, true},
		{"missing content consent", strings.Replace(base, `"acknowledgeLogContent":true,`, "", 1), false, false},
		{"false content consent", strings.Replace(base, `"acknowledgeLogContent":true`, `"acknowledgeLogContent":false`, 1), false, false},
		{"null consent", strings.Replace(base, `"acknowledgeLogContent":true`, `"acknowledgeLogContent":null`, 1), false, false},
		{"duplicate consent", strings.Replace(base, `"acknowledgeLogContent":true`, `"acknowledgeLogContent":false,"acknowledgeLogContent":true`, 1), false, false},
		{"noncanonical floor", strings.Replace(base, `"expectedFloor":"0"`, `"expectedFloor":"00"`, 1), false, false},
		{"query duplicate", strings.Replace(base, `"unit":"invented.service"`, `"unit":"unapproved.service","unit":"invented.service"`, 1), false, false},
		{"query alias", strings.Replace(base, `"unit"`, `"Unit"`, 1), false, false},
		{"query missing severity", strings.Replace(base, `,"maxPriority":3`, "", 1), false, false},
		{"query null severity", strings.Replace(base, `"maxPriority":3`, `"maxPriority":null`, 1), false, false},
		{"wildcard", strings.Replace(base, "invented.service", "*.service", 1), false, false},
		{"extra hook", strings.Replace(base, `"maxPriority":3`, `"maxPriority":3,"command":"anything"`, 1), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/journal/create", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			_, _, ok := readJournalCreate(w, r, now, tc.plaintext)
			if ok != tc.success {
				t.Fatal("unexpected acknowledgement/contract outcome")
			}
		})
	}
}
func TestJournalIdentityRejectsAmbiguousCAS(t *testing.T) {
	id := journalrequest.Identity{ID: "journal_" + strings.Repeat("1", 32), Sequence: 1, QueryDigest: "sha256:" + strings.Repeat("a", 64)}
	raw, _ := json.Marshal(id)
	var got journalrequest.Identity
	if !journalIdentity(raw, &got) || got != id {
		t.Fatal("valid identity rejected")
	}
	for _, b := range []string{strings.Replace(string(raw), `"sequence":"1"`, `"sequence":"01"`, 1), strings.Replace(string(raw), `"sequence":"1"`, `"sequence":null`, 1), strings.Replace(string(raw), `"sequence":"1"`, `"sequence":"2","sequence":"1"`, 1), strings.Replace(string(raw), `"id"`, `"ID"`, 1)} {
		if journalIdentity([]byte(b), &got) {
			t.Fatal("ambiguous identity accepted")
		}
	}
}
