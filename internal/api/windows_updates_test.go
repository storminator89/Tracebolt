package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsupdates"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type windowsUpdatesViewFixture struct {
	view      enrollmentstore.WindowsInventoryView
	now       time.Time
	afterRead func()
	reads     int
}

func (f *windowsUpdatesViewFixture) Now() time.Time { return f.now }
func (f *windowsUpdatesViewFixture) WindowsInventoryView(_ context.Context, id string, _ time.Time) (enrollmentstore.WindowsInventoryView, error) {
	f.reads++
	if f.afterRead != nil {
		f.afterRead()
	}
	return f.view, nil
}

func TestWindowsUpdatesOperatorSessionAndResponseTimeExpiry(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	seq := uint64(1)
	for _, kind := range []string{"fresh", "stale", "expired", "revoked-session", "canceled-request"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			active := true
			id := "agent_" + strings.Repeat("1", 32)
			view := enrollmentstore.EmptyWindowsInventoryView(id, at)
			view.Status = "fresh"
			view.Sequence = &seq
			view.ReceivedAt = &at
			view.Snapshot = &windowsmanaged.Snapshot{CollectedAt: at}
			view.Updates = &windowsupdates.Snapshot{SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope, GrantID: strings.Repeat("9", 32), GenerationID: "sample_" + strings.Repeat("1", 32), CollectedAt: at, Source: "wua-cache", CacheFreshness: "unknown", Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsupdates.Update{{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 1, Title: "Private cached update", KBArticleIDs: []string{"KB123456"}, Severity: "important"}}}
			f := &windowsUpdatesViewFixture{now: at, view: view}
			f.afterRead = func() {
				switch kind {
				case "stale":
					f.now = at.Add(3 * time.Minute)
				case "expired":
					f.now = at.Add(24 * time.Hour)
				case "revoked-session":
					active = false
				case "canceled-request":
					cancel()
				}
			}
			r := httptest.NewRequest("GET", "/api/devices/"+id+"/windows-inventory", nil).WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool { return active }}))
			w := httptest.NewRecorder()
			h := operatorHandler{app: setup(t)}
			h.writeWindowsInventoryView(w, r, f, id)
			if f.reads != 1 {
				t.Fatal("GET polled source or repeated retained read")
			}
			if kind == "revoked-session" || kind == "canceled-request" {
				if w.Code != 401 || strings.Contains(w.Body.String(), "Private cached update") || strings.Contains(w.Body.String(), "updates") {
					t.Fatal("session lost during read exposed private updates")
				}
				return
			}
			if w.Code != 200 {
				t.Fatal("retained view failed", w.Code)
			}
			var got enrollmentstore.WindowsInventoryView
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.ReceivedAt == nil || !got.ReceivedAt.Equal(at) {
				t.Fatal("response recheck refreshed receipt")
			}
			switch kind {
			case "fresh":
				if got.Updates == nil || got.Updates.CacheFreshness != "unknown" || got.Status != "fresh" {
					t.Fatal("cached evidence changed")
				}
			case "stale":
				if got.Updates == nil || !got.Updates.CollectedAt.Equal(at) || got.Status != "stale" {
					t.Fatal("stale capture refreshed")
				}
			case "expired":
				if got.Updates != nil || strings.Contains(w.Body.String(), "Private cached update") || got.Status != "unavailable" {
					t.Fatal("private capture survived original 24h limit")
				}
			}
		})
	}
}

func TestWindowsUpdatesResourceRequiresExistingOperatorRoute(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	path := "/api/devices/agent_" + strings.Repeat("1", 32) + "/windows-inventory"
	if response, _ := o.call(t, "GET", path, nil, "", nil); response.StatusCode != 401 {
		t.Fatal("anonymous Windows update surface reachable")
	}
	o.login(t)
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"GET", path, nil, 404}, {"POST", path, nil, 405}, {"GET", path + "?refresh=1", nil, 400},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		response, _ := o.call(t, tc.method, tc.path, nil, "", tc.change)
		if response.StatusCode != tc.want {
			t.Fatalf("%s %s: got %d, want %d", tc.method, tc.path, response.StatusCode, tc.want)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("private Windows view became cacheable")
		}
	}
	w := httptest.NewRecorder()
	o.app.api(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 404 {
		t.Fatal("Windows retained view exposed outside operator API")
	}
}
