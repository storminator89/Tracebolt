//go:build linux

package journalgenerationstate

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/journalgeneration"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureRecord() Record {
	return Record{SchemaVersion: Version, SenderBinding: strings.Repeat("a", 64), DeviceID: "agent_" + strings.Repeat("e", 32), CertificateHash: strings.Repeat("b", 64), PolicyGeneration: journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64)}}
}
func fixture(t *testing.T) (*State, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal-policy-generation")
	s, e := Initialize(context.Background(), dir, fixtureRecord())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func TestFloorsSurviveReopen(t *testing.T) {
	s, dir := fixture(t)
	r, _ := s.Record()
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	report, e := s.NextReport(context.Background(), r, at)
	if e != nil || report.Sequence != 1 || report.Tuple != r.PolicyGeneration {
		t.Fatal(report, e)
	}
	if _, e = s.NextReport(context.Background(), r, at); e != ErrBinding {
		t.Fatal("stale state accepted", e)
	}
	r, _ = s.Record()
	next := r.PolicyGeneration
	next.Revision = 2
	next.Generation = strings.Repeat("e", 64)
	next.PolicyDigest = "sha256:" + strings.Repeat("f", 64)
	if e = s.Advance(context.Background(), r, next); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, _ = s.Record()
	if r.PolicyGeneration != next || r.ReportSequence != 1 {
		t.Fatal(r)
	}
	report, e = s.NextReport(context.Background(), r, at.Add(time.Second))
	if e != nil || report.Sequence != 2 {
		t.Fatal(report, e)
	}
}
func TestRejectResetConflictsAndMissingState(t *testing.T) {
	s, dir := fixture(t)
	r, _ := s.Record()
	before, _ := os.ReadFile(filepath.Join(dir, stateName))
	for _, rev := range []uint64{0, 1, 2, 3} {
		g := r.PolicyGeneration
		g.Revision = rev
		if e := s.Advance(context.Background(), r, g); e == nil {
			t.Fatal("invalid transition admitted")
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, stateName))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected update changed state")
	}
	s.Close()
	if _, e := Initialize(context.Background(), dir, r); e == nil {
		t.Fatal("reinitialized")
	}
	if _, e := Open(context.Background(), dir+"-missing"); e == nil {
		t.Fatal("missing state adopted")
	}
	var zero State
	if _, e := zero.Record(); e != ErrClosed {
		t.Fatal(e)
	}
}
func TestFailureReturnsNoReportAndPoisonsCopies(t *testing.T) {
	for _, point := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(point, func(t *testing.T) {
			s, dir := fixture(t)
			copyState := *s
			r, _ := s.Record()
			disk := s.store.(*linuxStorage)
			base := disk.ops
			calls := 0
			disk.ops.sync = func(fd int) error {
				calls++
				if point == "file-sync" && calls == 1 || point == "directory-sync" && calls == 2 {
					return errors.New("injected")
				}
				return base.sync(fd)
			}
			disk.ops.rename = func(a int, b string, c int, d string) error {
				if point == "rename" {
					return errors.New("injected")
				}
				return base.rename(a, b, c, d)
			}
			report, e := s.NextReport(context.Background(), r, time.Now().UTC())
			if !errors.Is(e, ErrUncertain) || report.Sequence != 0 {
				t.Fatal(report, e)
			}
			if _, e = copyState.Record(); !errors.Is(e, ErrUncertain) {
				t.Fatal("copied handle revived", e)
			}
			s.Close()
			if point != "directory-sync" {
				if _, e = os.Lstat(filepath.Join(dir, tempName)); e != nil {
					t.Fatal("temporary removed")
				}
				if _, e = Open(context.Background(), dir); !errors.Is(e, ErrUncertain) {
					t.Fatal(e)
				}
			} else {
				fresh, e := Open(context.Background(), dir)
				if e != nil {
					t.Fatal(e)
				}
				defer fresh.Close()
				got, _ := fresh.Record()
				if got.ReportSequence != 1 {
					t.Fatal("recovered floor lost")
				}
			}
		})
	}
}
func TestUnsafeModesLinksAndTemporaries(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "hardlink", "unknown", "temporary", "missing", "lock-replaced", "directory-mode"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := fixture(t)
			s.Close()
			p := filepath.Join(dir, stateName)
			switch kind {
			case "mode":
				os.Chmod(p, 0644)
			case "symlink":
				os.Rename(p, p+"-original")
				os.Symlink(p+"-original", p)
			case "hardlink":
				os.Link(p, filepath.Join(t.TempDir(), "link"))
			case "unknown":
				os.WriteFile(filepath.Join(dir, "unknown"), []byte("x"), 0600)
			case "temporary":
				os.WriteFile(filepath.Join(dir, tempName), []byte("partial"), 0600)
			case "missing":
				os.Remove(p)
			case "lock-replaced":
				os.Remove(filepath.Join(dir, lockName))
				os.Mkdir(filepath.Join(dir, lockName), 0700)
			case "directory-mode":
				os.Chmod(dir, 0755)
			}
			if got, e := Open(context.Background(), dir); e == nil {
				got.Close()
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
func TestCanonicalAndInvalidTime(t *testing.T) {
	r := fixtureRecord()
	raw, e := encode(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"reportSequence":"0"`), []byte(`"reportSequence":0`), 1), bytes.Replace(raw, []byte(`"reportSequence":"0"`), []byte(`"reportSequence":"0","unknown":0`), 1)} {
		if _, e := decode(bad); e == nil {
			t.Fatal("malformed state admitted")
		}
	}
	s, _ := fixture(t)
	for _, at := range []time.Time{time.Time{}, time.Unix(1, 0).In(time.FixedZone("local", 3600)), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, e := s.NextReport(context.Background(), r, at); e == nil {
			t.Fatal("bad time")
		}
	}
	now, _ := s.Record()
	if now.ReportSequence != 0 {
		t.Fatal("bad time changed floor")
	}
}
