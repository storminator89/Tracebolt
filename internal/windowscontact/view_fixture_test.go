package windowscontact

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateViewFixture = flag.Bool("update-windows-contact-fixture", false, "regenerate the checked-in Go/TypeScript Windows contact view contract fixture")

// The web contract tests consume these exact Go-produced wire values. All
// receipts are inert fixtures; no enrolled device or host collection is used.
func TestWindowsContactViewWireFixture(t *testing.T) {
	in := input(base)
	empty := in
	empty.ReceivedAt, empty.Sequence = time.Time{}, 0
	views := map[string]View{"unknown": New().View(empty, base, epochA)}
	s := New()
	evaluate(t, &s, in, base)
	views["recent"] = s.View(in, base, epochA)
	evaluate(t, &s, in, base.Add(121*time.Second))
	views["pending"] = s.View(in, base.Add(121*time.Second), epochA)
	evaluate(t, &s, in, base.Add(181*time.Second))
	views["overdue"] = s.View(in, base.Add(181*time.Second), epochA)
	in.ReceivedAt, in.Sequence = base.Add(211*time.Second), 2
	evaluate(t, &s, in, base.Add(211*time.Second))
	evaluate(t, &s, in, base.Add(271*time.Second))
	views["recovered"] = s.View(in, base.Add(271*time.Second), epochA)
	wire, err := json.MarshalIndent(views, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-contact-view.json")
	if *updateViewFixture {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, wire, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatal("Windows contact Go/TypeScript wire fixture changed; review both contracts before regenerating with -update-windows-contact-fixture")
	}
}
