package lanclientstate

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestWindowsNetworkContextV5PreservesAllPriorBytesAndMarkers(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		old := diskRecord{Binding: testBinding, LastSequence: 17, WindowsFullProcessesUsed: mask&4 != 0, WindowsFullSoftwareUsed: mask&2 != 0, WindowsFullServicesUsed: mask&1 != 0}
		switch {
		case old.WindowsFullProcessesUsed:
			old.Version = 4
		case old.WindowsFullSoftwareUsed:
			old.Version = 3
		case old.WindowsFullServicesUsed:
			old.Version = 2
		default:
			old.Version = 1
		}
		raw, e := encodeRecord(old)
		if e != nil {
			t.Fatal(e)
		}
		got, e := decodeRecord(raw)
		if e != nil {
			t.Fatal(e)
		}
		again, e := encodeRecord(got)
		if e != nil || !bytes.Equal(raw, again) || got.WindowsNetworkContextUsed {
			t.Fatal("old bytes or authority changed")
		}
		next := old
		next.Version = 5
		next.WindowsNetworkContextUsed = true
		raw, e = encodeRecord(next)
		if e != nil {
			t.Fatal(e)
		}
		got, e = decodeRecord(raw)
		if e != nil || got != next {
			t.Fatal("v5 lost independent flags")
		}
		for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"windowsNetworkContextUsed":true`), []byte(`"windowsNetworkContextUsed":false`), 1), bytes.Replace(raw, []byte(`"windowsNetworkContextUsed":true,`), nil, 1), bytes.Replace(raw, []byte(`"windowsNetworkContextUsed":true`), []byte(`"windowsNetworkContextUsed":true,"windowsNetworkContextUsed":true`), 1)} {
			if _, e := decodeRecord(bad); e == nil {
				t.Fatal("ambiguous or missing used fence admitted")
			}
		}
		for version := 1; version <= 4; version++ {
			bad := next
			bad.Version = version
			raw, _ := json.Marshal(bad)
			if _, e := decodeRecord(raw); e == nil {
				t.Fatal("old version admitted network context")
			}
		}
	}
}

func TestWindowsNetworkContextAllFourMarkersAnyOrderPreserveExactPending(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inert Linux filesystem fixture; no native Windows state access")
	}
	var visit func([]int, []int)
	visit = func(prefix, left []int) {
		if len(left) > 0 {
			for i, v := range left {
				visit(append(append([]int{}, prefix...), v), append(append([]int{}, left[:i]...), left[i+1:]...))
			}
			return
		}
		dir := t.TempDir() + "/sender"
		s, e := InitializeNew(dir, testBinding)
		if e != nil {
			t.Fatal(e)
		}
		body := []byte(" {\"inert\":\"exact old telemetry\"} \n")
		pending, e := s.Stage(1, body)
		if e != nil {
			t.Fatal(e)
		}
		s.Close()
		seen := [4]bool{}
		for _, kind := range prefix {
			var lease interface {
				Mark() error
				Close() error
			}
			switch kind {
			case 0:
				lease, e = AcquireWindowsFullServicesInitialization(dir, testBinding)
			case 1:
				lease, e = AcquireWindowsFullSoftwareInitialization(dir, testBinding)
			case 2:
				lease, e = AcquireWindowsFullProcessesInitialization(dir, testBinding)
			case 3:
				lease, e = AcquireWindowsNetworkContextInitialization(dir, testBinding)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = lease.Mark(); e != nil {
				t.Fatal(e)
			}
			if e = lease.Mark(); e != nil {
				t.Fatal("non-idempotent marker")
			}
			lease.Close()
			seen[kind] = true
			s, e = OpenExisting(dir, testBinding)
			if e != nil {
				t.Fatal(e)
			}
			a, _ := s.WindowsFullServicesUsed()
			b, _ := s.WindowsFullSoftwareUsed()
			c, _ := s.WindowsFullProcessesUsed()
			d, _ := s.WindowsNetworkContextUsed()
			got, e := s.Pending()
			if e != nil || [4]bool{a, b, c, d} != seen || got == nil || got.Digest != pending.Digest || got.Sequence != pending.Sequence || !bytes.Equal(got.Body(), body) {
				t.Fatal("marker changed authority or exact pending")
			}
			v, e := s.locked()
			if e != nil {
				t.Fatal(e)
			}
			if seen[3] && v.record.Version != 5 {
				t.Fatal("network marker downgraded")
			}
			v.mu.Unlock()
			s.Close()
		}
	}
	visit(nil, []int{0, 1, 2, 3})
}
