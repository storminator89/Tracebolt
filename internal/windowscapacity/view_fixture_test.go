package windowscapacity

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateCapacityFixture = flag.Bool("update-windows-capacity-fixture", false, "regenerate reviewed Go/TypeScript Windows capacity wire fixture")

func TestWindowsCapacityViewWireFixture(t *testing.T) {
	views := map[string]View{}
	s := New()
	views["disabled"] = s.View(input(95, 0), at, epoch)
	s = configured(t)
	views["unknown"] = s.View(input(95, 0), at, epoch)
	evaluate(t, &s, input(95, 0), 0)
	views["pending"] = s.View(input(95, 0), at, epoch)
	evaluate(t, &s, input(95, 30), 30)
	evaluate(t, &s, input(95, 60), 60)
	views["pressure"] = s.View(input(95, 60), at.Add(time.Minute), epoch)
	in := input(20, 90)
	in.Disk.Quality = "partial"
	evaluate(t, &s, in, 90)
	views["unknownOpen"] = s.View(in, at.Add(90*time.Second), epoch)
	for _, sec := range []int{120, 150, 180} {
		evaluate(t, &s, input(80, sec), sec)
	}
	views["recovered"] = s.View(input(80, 180), at.Add(180*time.Second), epoch)
	for _, sec := range []int{210, 240, 270} {
		evaluate(t, &s, input(95, sec), sec)
	}
	if e := s.Configure(input(95, 300), false, 90, 1, at.Add(300*time.Second)); e != nil {
		t.Fatal(e)
	}
	views["policyChanged"] = s.View(input(95, 300), at.Add(300*time.Second), epoch)
	raw, e := json.MarshalIndent(views, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-capacity-view.json")
	if *updateCapacityFixture {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	stored, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(stored, raw) {
		t.Fatal("capacity Go/TypeScript contract fixture changed; review both before regeneration")
	}
}
