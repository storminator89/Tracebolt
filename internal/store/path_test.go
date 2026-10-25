package store

import (
	"localrmm/internal/fixtures"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDatabaseURIUsesExactNativePath(t *testing.T) {
	for _, name := range []string{"state.db", "state with spaces.db", "state # percent % & ü.db"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nested directory", name)
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			devices, cases := fixtures.Seed(time.Now())
			if err = db.Seed(devices, cases); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Mutate(cases[0].ID, "note", "Synthetic path-persistence fixture"); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatal("database was not created at its exact requested path", err)
			}
			db, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			c, err := db.Case(cases[0].ID)
			if err != nil || len(c.Notes) != 1 || c.Notes[0].Text != "Synthetic path-persistence fixture" {
				t.Fatal("escaped native path did not retain the original database", err)
			}
		})
	}
}
