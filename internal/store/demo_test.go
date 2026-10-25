package store

import (
	"fmt"
	"localrmm/internal/model"
	"path/filepath"
	"testing"
)

func TestSyntheticDemoCheckIncludesRowsPastListLimit(t *testing.T) {
	for _, kind := range []string{"devices", "cases"} {
		t.Run(kind, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			devices := make([]model.Device, 0, 1000)
			cases := make([]model.Case, 0, 1000)
			for i := 0; i < 1000; i++ {
				if kind == "devices" {
					devices = append(devices, model.Device{ID: fmt.Sprintf("fixture-%d", i), Synthetic: true, Source: "synthetic"})
				} else {
					cases = append(cases, model.Case{ID: fmt.Sprintf("fixture-%d", i), Synthetic: true})
				}
			}
			if err = db.Seed(devices, cases); err != nil {
				t.Fatal(err)
			}
			if err = db.RequireSyntheticDemo(); err != nil {
				t.Fatal("pure synthetic state was rejected", err)
			}
			if kind == "devices" {
				devices = []model.Device{{ID: "hidden-real-row", Source: "local"}}
				cases = nil
			} else {
				devices = nil
				cases = []model.Case{{ID: "hidden-real-row", Synthetic: false}}
			}
			if err = db.Seed(devices, cases); err != nil {
				t.Fatal(err)
			}
			if err = db.RequireSyntheticDemo(); err == nil {
				t.Fatal("non-synthetic row behind the 1000-row UI limit was missed")
			}
		})
	}
}
