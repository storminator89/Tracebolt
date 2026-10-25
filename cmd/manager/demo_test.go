package main

import (
	"encoding/json"
	"localrmm/internal/fixtures"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestDevelopmentModeSelectsCollectionBeforeFirstSample(t *testing.T) {
	for _, tc := range []struct {
		name          string
		demo, preview bool
		calls, rows   int
		invalid       bool
	}{
		{"default keeps its local collector", false, false, 1, 8, false},
		{"demo only never calls the collector", true, false, 0, 7, false},
		{"managed preview never calls the collector", false, true, 0, 8, false},
		{"conflicting modes fail before collection", true, true, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			devices, cases := fixtures.Seed(time.Now())
			if err = db.Seed(devices, cases); err != nil {
				t.Fatal(err)
			}
			calls := 0
			handler, err := newDevelopmentHandler(db, 8787, t.TempDir(), tc.demo, tc.preview, func() model.Device {
				calls++
				return model.Device{ID: "injected-local-sample", Source: "local"}
			})
			if calls != tc.calls || (err != nil) != tc.invalid {
				t.Fatalf("collection calls=%d, error=%v", calls, err)
			}
			if tc.invalid {
				return
			}
			read := func(path string, output any) {
				t.Helper()
				r := httptest.NewRequest("GET", "http://127.0.0.1:8787"+path, nil)
				r.RemoteAddr = "127.0.0.1:12345"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), output) != nil {
					t.Fatalf("%s returned %d", path, w.Code)
				}
			}
			var list struct{ Items []model.Device }
			read("/api/devices", &list)
			if len(list.Items) != tc.rows {
				t.Fatalf("got %d devices, want %d", len(list.Items), tc.rows)
			}
			if tc.demo {
				for _, d := range list.Items {
					if !d.Synthetic || d.Source != "synthetic" {
						t.Fatal("demo exposed a non-synthetic device")
					}
				}
			}
			var capabilities struct {
				DemoOnly, ManagedPreview bool
			}
			read("/api/capabilities", &capabilities)
			if capabilities.DemoOnly != tc.demo || capabilities.ManagedPreview != tc.preview {
				t.Fatal("mode metadata does not describe the actual source")
			}
		})
	}
}

func TestDemoOnlyRejectsExistingStateBeforeSeeding(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Seed([]model.Device{{ID: "existing-real", Source: "local"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err = seedDevelopmentFixtures(db, true, time.Now()); err == nil {
		t.Fatal("mixed database was accepted")
	}
	devices, _ := db.Devices()
	cases, _ := db.Cases()
	if len(devices) != 1 || devices[0].ID != "existing-real" || len(cases) != 0 {
		t.Fatal("rejected startup inserted fixtures into existing state")
	}
}
