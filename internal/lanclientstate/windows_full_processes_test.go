package lanclientstate

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestWindowsFullProcessesMarkerPreservesV1BytesAndPending(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inert Linux filesystem fixture; no native Windows state access")
	}
	legacy := diskRecord{Version: stateVersion, Binding: testBinding, LastSequence: 17}
	raw, e := encodeRecord(legacy)
	if e != nil {
		t.Fatal(e)
	}
	want := []byte(`{"version":1,"binding":"` + testBinding + `","lastSequence":17,"pending":null}`)
	if !bytes.Equal(raw, want) {
		t.Fatal("untouched v1 encoding changed")
	}
	dir := t.TempDir() + "/sender"
	s, e := InitializeNew(dir, testBinding)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte(" {\"invented\": \"original pending bytes\"} \n")
	pending, e := s.Stage(1, body)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	lease, e := AcquireWindowsFullProcessesInitialization(dir, testBinding)
	if e != nil {
		t.Fatal(e)
	}
	used, e := lease.Used()
	if e != nil || used {
		t.Fatal("marker was automatic")
	}
	if e = lease.Mark(); e != nil {
		t.Fatal(e)
	}
	if e = lease.Mark(); e != nil {
		t.Fatal("mark not idempotent")
	}
	lease.Close()
	s, e = OpenExisting(dir, testBinding)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	used, e = s.WindowsFullProcessesUsed()
	if e != nil || !used {
		t.Fatal("used fence lost")
	}
	got, e := s.Pending()
	if e != nil || got == nil || got.Sequence != pending.Sequence || got.Digest != pending.Digest || !bytes.Equal(got.Body(), body) {
		t.Fatal("marker changed original telemetry")
	}
	if seq, e := s.NextSequence(); e != nil || seq != 2 {
		t.Fatal("marker reset telemetry sequence")
	}
	if e = s.Acknowledge(pending.Digest); e != nil {
		t.Fatal(e)
	}
	if used, e = s.WindowsFullProcessesUsed(); e != nil || !used {
		t.Fatal("ack erased permanent marker")
	}
}
func TestWindowsFullProcessesMarkerStrictVersionBoundary(t *testing.T) {
	legacy := diskRecord{Version: 1, Binding: testBinding}
	raw, _ := json.Marshal(legacy)
	if _, e := decodeRecord(raw); e != nil {
		t.Fatal(e)
	}
	valid := diskRecord{Version: 4, Binding: testBinding, WindowsFullProcessesUsed: true}
	raw, _ = encodeRecord(valid)
	if decoded, e := decodeRecord(raw); e != nil || !decoded.WindowsFullProcessesUsed {
		t.Fatal("v4 marker rejected", e)
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"windowsFullProcessesUsed":true`), []byte(`"windowsFullProcessesUsed":false`), 1), bytes.Replace(raw, []byte(`"version":4`), []byte(`"version":1`), 1), bytes.Replace(raw, []byte(`"windowsFullProcessesUsed":true,`), nil, 1), bytes.Replace(raw, []byte(`"windowsFullProcessesUsed":true`), []byte(`"windowsFullProcessesUsed":true,"windowsFullProcessesUsed":true`), 1)} {
		if _, e := decodeRecord(bad); e == nil {
			t.Fatal("downgraded/missing/ambiguous marker accepted")
		}
	}
}

func TestWindowsAllThreeGenerationMarkersRemainIndependentInAnyOrder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inert filesystem fixture")
	}
	for _, order := range [][3]string{{"processes", "software", "services"}, {"processes", "services", "software"}, {"software", "processes", "services"}, {"software", "services", "processes"}, {"services", "processes", "software"}, {"services", "software", "processes"}} {
		t.Run(order[0]+"-"+order[1]+"-"+order[2], func(t *testing.T) {
			dir := t.TempDir() + "/sender"
			s, e := InitializeNew(dir, testBinding)
			if e != nil {
				t.Fatal(e)
			}
			body := []byte(" {\"inert\": \"unaltered exact pending telemetry\"} \n")
			pending, e := s.Stage(1, body)
			if e != nil {
				t.Fatal(e)
			}
			s.Close()
			seen := map[string]bool{}
			for _, kind := range order {
				switch kind {
				case "processes":
					l, e := AcquireWindowsFullProcessesInitialization(dir, testBinding)
					if e != nil {
						t.Fatal(e)
					}
					if e = l.Mark(); e != nil {
						t.Fatal(e)
					}
					l.Close()
				case "software":
					l, e := AcquireWindowsFullSoftwareInitialization(dir, testBinding)
					if e != nil {
						t.Fatal(e)
					}
					if e = l.Mark(); e != nil {
						t.Fatal(e)
					}
					l.Close()
				case "services":
					l, e := AcquireWindowsFullServicesInitialization(dir, testBinding)
					if e != nil {
						t.Fatal(e)
					}
					if e = l.Mark(); e != nil {
						t.Fatal(e)
					}
					l.Close()
				}
				seen[kind] = true
				s, e = OpenExisting(dir, testBinding)
				if e != nil {
					t.Fatal(e)
				}
				p, _ := s.WindowsFullProcessesUsed()
				w, _ := s.WindowsFullSoftwareUsed()
				v, _ := s.WindowsFullServicesUsed()
				got, e := s.Pending()
				if e != nil || p != seen["processes"] || w != seen["software"] || v != seen["services"] || got == nil || got.Sequence != pending.Sequence || got.Digest != pending.Digest || !bytes.Equal(got.Body(), body) {
					t.Fatal("marker changed another scope or pending bytes", kind, e)
				}
				value, e := s.locked()
				if e != nil {
					t.Fatal(e)
				}
				if seen["processes"] && value.record.Version != 4 {
					t.Fatal("process version downgraded")
				}
				value.mu.Unlock()
				s.Close()
			}
		})
	}
}

func TestWindowsProcessMarkerPreservesEveryLegacyPrimaryEncoding(t *testing.T) {
	type priorRecord struct {
		WindowsFullSoftwareUsed bool         `json:"windowsFullSoftwareUsed,omitempty"`
		WindowsFullServicesUsed bool         `json:"windowsFullServicesUsed,omitempty"`
		Version                 int          `json:"version"`
		Binding                 string       `json:"binding"`
		LastSequence            uint64       `json:"lastSequence"`
		Pending                 *diskPending `json:"pending"`
	}
	for _, old := range []priorRecord{{Version: 1, Binding: testBinding}, {Version: 2, Binding: testBinding, WindowsFullServicesUsed: true}, {Version: 3, Binding: testBinding, WindowsFullSoftwareUsed: true}, {Version: 3, Binding: testBinding, WindowsFullSoftwareUsed: true, WindowsFullServicesUsed: true}} {
		raw, e := json.Marshal(old)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := decodeRecord(raw)
		if e != nil {
			t.Fatal(e)
		}
		exact, e := encodeRecord(decoded)
		if e != nil || !bytes.Equal(raw, exact) || decoded.WindowsFullProcessesUsed {
			t.Fatal("old primary bytes or authority changed", old.Version, e)
		}
	}
	for _, version := range []int{1, 2, 3} {
		raw, _ := json.Marshal(diskRecord{Version: version, Binding: testBinding, WindowsFullProcessesUsed: true, WindowsFullSoftwareUsed: true, WindowsFullServicesUsed: true})
		if _, e := decodeRecord(raw); e == nil {
			t.Fatal("old primary version accepted process marker", version)
		}
	}
	for _, software := range []bool{false, true} {
		for _, services := range []bool{false, true} {
			record := diskRecord{Version: 4, Binding: testBinding, WindowsFullProcessesUsed: true, WindowsFullSoftwareUsed: software, WindowsFullServicesUsed: services}
			raw, e := encodeRecord(record)
			if e != nil {
				t.Fatal(e)
			}
			got, e := decodeRecord(raw)
			if e != nil || got.WindowsFullSoftwareUsed != software || got.WindowsFullServicesUsed != services || !got.WindowsFullProcessesUsed {
				t.Fatal("independent v4 shape rejected", software, services, e)
			}
		}
	}
}
