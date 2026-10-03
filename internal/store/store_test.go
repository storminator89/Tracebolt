package store

import (
	"localrmm/internal/fixtures"
	"localrmm/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableMutationAndSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ds, cs := fixtures.Seed(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	if e = s.Seed(ds, cs); e != nil {
		t.Fatal(e)
	}
	text := "literal <script>alert('x')</script> and '); DROP TABLE cases;--"
	if _, e = s.Mutate(cs[0].ID, "note", text); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Mutate(cs[0].ID, "status", "investigating"); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Seed(ds, cs); e != nil {
		t.Fatal(e)
	}
	c, e := s.Case(cs[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	if c.Status != "investigating" || len(c.Notes) != 1 || c.Notes[0].Text != text {
		t.Fatalf("state not retained: %+v", c)
	}
	if _, e = s.Case("x' OR 1=1--"); e != ErrNotFound {
		t.Fatal("parameterization boundary failed", e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("database permissions", info, e)
	}
}
func TestNoteLimit(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ds, cs := fixtures.Seed(time.Now())
	cs[0].Notes = make([]model.Note, 100)
	if e = s.Seed(ds, cs); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Mutate(cs[0].ID, "note", "extra"); e != ErrLimit {
		t.Fatal(e)
	}
}
