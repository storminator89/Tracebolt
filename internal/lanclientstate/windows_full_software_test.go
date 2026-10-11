package lanclientstate

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestWindowsFullSoftwareMarkerPreservesV1BytesAndPending(t *testing.T) {
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
	lease, e := AcquireWindowsFullSoftwareInitialization(dir, testBinding)
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
	used, e = s.WindowsFullSoftwareUsed()
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
	if used, e = s.WindowsFullSoftwareUsed(); e != nil || !used {
		t.Fatal("ack erased permanent marker")
	}
}
func TestWindowsFullSoftwareMarkerStrictVersionBoundary(t *testing.T) {
	legacy := diskRecord{Version: 1, Binding: testBinding}
	raw, _ := json.Marshal(legacy)
	if _, e := decodeRecord(raw); e != nil {
		t.Fatal(e)
	}
	valid := diskRecord{Version: 3, Binding: testBinding, WindowsFullSoftwareUsed: true}
	raw, _ = encodeRecord(valid)
	if decoded, e := decodeRecord(raw); e != nil || !decoded.WindowsFullSoftwareUsed {
		t.Fatal("v3 marker rejected", e)
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"windowsFullSoftwareUsed":true`), []byte(`"windowsFullSoftwareUsed":false`), 1), bytes.Replace(raw, []byte(`"version":3`), []byte(`"version":1`), 1), bytes.Replace(raw, []byte(`"windowsFullSoftwareUsed":true,`), nil, 1), bytes.Replace(raw, []byte(`"windowsFullSoftwareUsed":true`), []byte(`"windowsFullSoftwareUsed":true,"windowsFullSoftwareUsed":true`), 1)} {
		if _, e := decodeRecord(bad); e == nil {
			t.Fatal("downgraded/missing/ambiguous marker accepted")
		}
	}
}

func TestWindowsSoftwareAndServiceUsedMarkersRemainIndependent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inert filesystem fixture")
	}
	for _, softwareFirst := range []bool{true, false} {
		dir := t.TempDir() + "/sender"
		s, e := InitializeNew(dir, testBinding)
		if e != nil {
			t.Fatal(e)
		}
		pending, e := s.Stage(1, []byte("{\"invented\":true}"))
		if e != nil {
			t.Fatal(e)
		}
		s.Close()
		markSoftware := func() {
			lease, e := AcquireWindowsFullSoftwareInitialization(dir, testBinding)
			if e != nil {
				t.Fatal(e)
			}
			if e = lease.Mark(); e != nil {
				t.Fatal(e)
			}
			lease.Close()
		}
		markServices := func() {
			lease, e := AcquireWindowsFullServicesInitialization(dir, testBinding)
			if e != nil {
				t.Fatal(e)
			}
			if e = lease.Mark(); e != nil {
				t.Fatal(e)
			}
			lease.Close()
		}
		if softwareFirst {
			markSoftware()
		} else {
			markServices()
		}
		s, e = OpenExisting(dir, testBinding)
		if e != nil {
			t.Fatal(e)
		}
		software, _ := s.WindowsFullSoftwareUsed()
		services, _ := s.WindowsFullServicesUsed()
		s.Close()
		if software != softwareFirst || services == softwareFirst {
			t.Fatal("one marker promoted another")
		}
		if softwareFirst {
			markServices()
		} else {
			markSoftware()
		}
		s, e = OpenExisting(dir, testBinding)
		if e != nil {
			t.Fatal(e)
		}
		software, _ = s.WindowsFullSoftwareUsed()
		services, _ = s.WindowsFullServicesUsed()
		got, _ := s.Pending()
		if !software || !services || got == nil || got.Digest != pending.Digest || !bytes.Equal(got.Body(), pending.Body()) {
			t.Fatal("combined markers lost original identity/pending")
		}
		s.Close()
	}
}
