package lanclientstate

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestWindowsUserSoftwareV6PreservesAllPriorBytes(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		old := diskRecord{Binding: testBinding, LastSequence: 17, WindowsNetworkContextUsed: mask&8 != 0, WindowsFullProcessesUsed: mask&4 != 0, WindowsFullSoftwareUsed: mask&2 != 0, WindowsFullServicesUsed: mask&1 != 0}
		switch {
		case old.WindowsNetworkContextUsed:
			old.Version = 5
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
		if e != nil || !bytes.Equal(raw, again) || got.WindowsUserSoftwareUsed {
			t.Fatal("old bytes or authority changed")
		}
		next := old
		next.Version = 6
		next.WindowsUserSoftwareUsed = true
		raw, e = encodeRecord(next)
		if e != nil {
			t.Fatal(e)
		}
		got, e = decodeRecord(raw)
		if e != nil || got != next {
			t.Fatal("v6 lost independent markers")
		}
		for _, replacement := range []string{`"windowsUserSoftwareUsed":false`, `"windowsUserSoftwareUsed":null`, `"windowsUserSoftwareUsed":true,"windowsUserSoftwareUsed":true`, `"WindowsUserSoftwareUsed":true`} {
			bad := bytes.Replace(raw, []byte(`"windowsUserSoftwareUsed":true`), []byte(replacement), 1)
			if _, e := decodeRecord(bad); e == nil {
				t.Fatal("invalid fence admitted")
			}
		}
		if _, e := decodeRecord(bytes.Replace(raw, []byte(`"windowsUserSoftwareUsed":true,`), nil, 1)); e == nil {
			t.Fatal("missing fence admitted")
		}
		for version := 1; version <= 5; version++ {
			bad := next
			bad.Version = version
			b, _ := json.Marshal(bad)
			if _, e := decodeRecord(b); e == nil {
				t.Fatal("old version admitted new scope")
			}
		}
	}
}

func TestWindowsUserSoftwareFenceBeforeOtherScopesPreservesPending(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inert Linux fixture only")
	}
	dir := t.TempDir() + "/sender"
	s, e := InitializeNew(dir, testBinding)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte(" {\"inert\":\"exact telemetry\"} \n")
	pending, e := s.Stage(1, body)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	user, e := AcquireWindowsUserSoftwareInitialization(dir, testBinding)
	if e != nil || user.Mark() != nil || user.Mark() != nil || user.Close() != nil {
		t.Fatal("user marker")
	}
	factories := []func(string, string) (interface {
		Mark() error
		Close() error
	}, error){
		func(d, b string) (interface {
			Mark() error
			Close() error
		}, error) { return AcquireWindowsFullServicesInitialization(d, b) },
		func(d, b string) (interface {
			Mark() error
			Close() error
		}, error) { return AcquireWindowsFullSoftwareInitialization(d, b) },
		func(d, b string) (interface {
			Mark() error
			Close() error
		}, error) { return AcquireWindowsFullProcessesInitialization(d, b) },
		func(d, b string) (interface {
			Mark() error
			Close() error
		}, error) { return AcquireWindowsNetworkContextInitialization(d, b) },
	}
	for _, open := range factories {
		l, e := open(dir, testBinding)
		if e != nil || l.Mark() != nil || l.Close() != nil {
			t.Fatal("older scope marker")
		}
	}
	s, e = OpenExisting(dir, testBinding)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Pending()
	if e != nil || got == nil || got.Digest != pending.Digest || got.Sequence != pending.Sequence || !bytes.Equal(got.Body(), body) {
		t.Fatal("pending changed")
	}
	v, e := s.locked()
	if e != nil {
		t.Fatal(e)
	}
	defer v.mu.Unlock()
	if v.record.Version != 6 || !v.record.WindowsUserSoftwareUsed || !v.record.WindowsNetworkContextUsed || !v.record.WindowsFullProcessesUsed || !v.record.WindowsFullSoftwareUsed || !v.record.WindowsFullServicesUsed {
		t.Fatal("fences lost or version downgraded")
	}
}
