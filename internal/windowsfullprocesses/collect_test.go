package windowsfullprocesses

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

type fixtureSnapshot struct {
	rows                  []nativeEntry
	offset, calls, closed int
	err                   error
	after                 func()
}

func (s *fixtureSnapshot) next(context.Context) (nativeEntry, bool, error) {
	s.calls++
	if s.after != nil {
		s.after()
	}
	if s.err != nil {
		return nativeEntry{}, false, s.err
	}
	if s.offset == len(s.rows) {
		return nativeEntry{}, true, nil
	}
	r := s.rows[s.offset]
	s.offset++
	return r, false, nil
}
func (s *fixtureSnapshot) close() { s.closed++ }
func entry(pid uint32, name string) nativeEntry {
	r := nativeEntry{pid: pid, parentPID: pid / 2, threads: 3}
	copy(r.name[:], utf16.Encode([]rune(name)))
	return r
}
func readFixture(t *testing.T, s *fixtureSnapshot) (Capture, error) {
	t.Helper()
	at := testConsent().ChangedAt
	return collectSnapshot(context.Background(), func(context.Context) (processSnapshot, error) { return s, nil }, func() time.Time { return at })
}
func TestCompleteSnapshotBeyondPreviewAndExactRowCeiling(t *testing.T) {
	for _, n := range []int{0, 129, 2049, MaxRows} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := &fixtureSnapshot{}
			for i := n - 1; i >= 0; i-- {
				s.rows = append(s.rows, entry(uint32(i), "worker.exe"))
			}
			c, e := readFixture(t, s)
			if e != nil || !c.Complete || len(c.Rows) != n || c.Reason != "" || s.calls != n+1 || s.closed != 1 {
				t.Fatalf("complete=%v rows=%d calls=%d closes=%d reason=%s err=%v", c.Complete, len(c.Rows), s.calls, s.closed, c.Reason, e)
			}
			for i, r := range c.Rows {
				if r.PID != uint32(i) || r.ParentPID != uint32(i/2) || r.Threads != 3 {
					t.Fatal("snapshot identity/order altered")
				}
			}
		})
	}
}
func TestCutoffsAndEnumerationFailuresNeverPromotePrefix(t *testing.T) {
	tests := []struct {
		name   string
		rows   []nativeEntry
		err    error
		reason string
	}{
		{"duplicate", []nativeEntry{entry(3, "a"), entry(3, "b")}, nil, "source_changed"},
		{"allocation", nil, ErrBudget, "resource_limit"}, {"denied", nil, ErrDenied, "access_denied"}, {"unsupported", nil, ErrUnsupported, "unsupported"}, {"unavailable", nil, errors.New("provider-private"), "unavailable"},
	}
	many := make([]nativeEntry, MaxRows+1)
	for i := range many {
		many[i] = entry(uint32(i), "p")
	}
	tests = append(tests, struct {
		name   string
		rows   []nativeEntry
		err    error
		reason string
	}{"row-limit", many, nil, "resource_limit"})
	large := make([]nativeEntry, MaxRows)
	for i := range large {
		large[i] = entry(uint32(i), strings.Repeat("<", 259))
	}
	tests = append(tests, struct {
		name   string
		rows   []nativeEntry
		err    error
		reason string
	}{"byte-limit", large, nil, "resource_limit"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &fixtureSnapshot{rows: tt.rows, err: tt.err}
			c, e := readFixture(t, s)
			if e == nil || c.Complete || len(c.Rows) != 0 || c.Reason != tt.reason || s.closed != 1 || s.calls > MaxNativeReads {
				t.Fatalf("capture %v, %v", c, e)
			}
		})
	}
}
func TestSnapshotDeadlineIncludesOpenAndReadAndClosesOnce(t *testing.T) {
	for _, during := range []string{"open", "read", "regression", "cancel"} {
		t.Run(during, func(t *testing.T) {
			at := testConsent().ChangedAt
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &fixtureSnapshot{rows: []nativeEntry{entry(0, "idle")}}
			if during == "read" {
				s.after = func() { at = at.Add(CaptureTimeout + time.Nanosecond) }
			}
			if during == "regression" {
				s.after = func() { at = at.Add(-time.Second) }
			}
			if during == "cancel" {
				s.after = cancel
			}
			c, e := collectSnapshot(ctx, func(context.Context) (processSnapshot, error) {
				if during == "open" {
					at = at.Add(CaptureTimeout + time.Nanosecond)
				}
				return s, nil
			}, func() time.Time { return at })
			want := "deadline"
			if during == "regression" {
				want = "malformed_source"
			}
			if during == "cancel" {
				want = "canceled"
			}
			if e == nil || c.Complete || len(c.Rows) != 0 || c.Reason != want || s.closed != 1 {
				t.Fatalf("capture %v, %v", c, e)
			}
		})
	}
}
func TestInvalidNativeNameRetainsSnapshotPIDWithoutPathOrGuess(t *testing.T) {
	cases := [][NativeNameUnits]uint16{{}, {0xD800, 0}, {0xDC00, 0}}
	var unterminated [NativeNameUnits]uint16
	for i := range unterminated {
		unterminated[i] = 'x'
	}
	cases = append(cases, unterminated)
	for _, name := range []string{`C:\private\app.exe`, `dir/app.exe`} {
		r := entry(7, name)
		cases = append(cases, r.name)
	}
	for _, name := range cases {
		s := &fixtureSnapshot{rows: []nativeEntry{{pid: 7, parentPID: 3, threads: 0, name: name}}}
		c, e := readFixture(t, s)
		if e != nil || !c.Complete || len(c.Rows) != 1 || c.Rows[0].PID != 7 || c.Rows[0].Name != nil || c.Rows[0].NameQuality != "unavailable" {
			t.Fatalf("lost unavailable-name identity: %v %v", c, e)
		}
	}
	for _, name := range []string{"System Idle Process", strings.Repeat("x", 259), "😀α.exe"} {
		s := &fixtureSnapshot{rows: []nativeEntry{entry(7, name)}}
		c, e := readFixture(t, s)
		if e != nil || c.Rows[0].Name == nil || *c.Rows[0].Name != name {
			t.Fatal("valid native name changed")
		}
	}
}
func TestNativeCollectorRestrictedAPISurface(t *testing.T) {
	raw, e := os.ReadFile("collect_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(raw)
	for _, v := range []string{"windows.TH32CS_SNAPPROCESS", "windows.Process32First", "windows.Process32Next", "windows.CloseHandle"} {
		if !strings.Contains(s, v) {
			t.Fatalf("required API missing: %s", v)
		}
	}
	for _, v := range []string{"windows.OpenProcess(", "AdjustTokenPrivileges(", "QueryFullProcessImageName(", "GetProcessTimes(", "GetProcessMemoryInfo(", "os/exec", "TH32CS_SNAPMODULE", "TH32CS_SNAPHEAPLIST"} {
		if strings.Contains(s, v) {
			t.Fatalf("unexpected authority: %s", v)
		}
	}
}
