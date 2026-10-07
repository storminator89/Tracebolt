package windowsinventory

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
)

type fixture struct {
	calls         []string
	cpuCount      int
	cpuErr        error
	processResult result[Process]
}

func (p *fixture) called(name string) { p.calls = append(p.calls, name) }
func (p *fixture) system() model.Device {
	p.called("system")
	return model.Device{OS: "Windows NT 10.0 (build 26100)", Uptime: "1d 0h 0m", LastSeen: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)}
}
func (p *fixture) cpu() (cpuTimes, error) {
	p.called("cpu")
	p.cpuCount++
	if p.cpuCount == 1 {
		return cpuTimes{100, 200, 100}, p.cpuErr
	}
	return cpuTimes{125, 250, 150}, p.cpuErr
}
func (p *fixture) hostname() result[Hostname] {
	p.called("hostname")
	return result[Hostname]{rows: []Hostname{{Value: "TEST-PC"}}, complete: true}
}
func (p *fixture) processes(context.Context) result[Process] {
	p.called("processes")
	return p.processResult
}
func (p *fixture) services(context.Context) result[Service] {
	p.called("services")
	return result[Service]{rows: []Service{{Name: "Example", DisplayName: "Example service", State: "running", PID: 10}}, complete: true}
}
func (p *fixture) software(context.Context) result[Software] {
	p.called("software")
	return result[Software]{rows: []Software{{Name: "Invented program", Version: "1.2", Publisher: "Example", RegistryView: "64"}}, complete: true}
}
func (p *fixture) network(context.Context) result[InterfaceAddress] {
	p.called("network")
	return result[InterfaceAddress]{rows: []InterfaceAddress{{Index: 1, Name: "Ethernet", Address: "192.0.2.10", PrefixLength: 24}}, complete: true}
}
func noWait(context.Context) error { return nil }

func TestCPUIntervalValidation(t *testing.T) {
	cases := []struct {
		name          string
		before, after cpuTimes
		want          float64
		ok            bool
	}{
		{"normal", cpuTimes{100, 200, 100}, cpuTimes{125, 250, 150}, 75, true},
		{"all idle", cpuTimes{}, cpuTimes{100, 100, 0}, 0, true},
		{"busy", cpuTimes{}, cpuTimes{0, 100, 100}, 100, true},
		{"zero", cpuTimes{}, cpuTimes{}, 0, false},
		{"reset", cpuTimes{100, 200, 100}, cpuTimes{10, 250, 200}, 0, false},
		{"idle outside kernel", cpuTimes{}, cpuTimes{200, 100, 200}, 0, false},
		{"sum overflow", cpuTimes{}, cpuTimes{0, math.MaxUint64, 1}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := cpuPercent(c.before, c.after)
			if ok != c.ok || got != c.want {
				t.Fatal("CPU interval validation mismatch")
			}
		})
	}
}
func TestCompositionScopeAndSource(t *testing.T) {
	p := &fixture{processResult: result[Process]{rows: []Process{{PID: 11, Name: "later.exe"}, {PID: 2, Name: "first.exe"}}, complete: true}}
	r, err := collect(context.Background(), p, noWait)
	if err != nil || r.Schema != Schema || r.Platform != "windows" || r.CPU.Value == nil || *r.CPU.Value != 75 || r.CPU.Source != cpuSource {
		t.Fatal("invalid observation contract")
	}
	if r.Processes.Rows[0].PID != 2 || !r.Processes.Complete || r.Processes.Quality != "healthy" {
		t.Fatal("invalid process composition")
	}
	if r.NativeVerification != "installed-service-and-enrollment-unverified" || !strings.Contains(r.Services.Scope, "silently omitted") || !strings.Contains(r.Software.Scope, "per-user") {
		t.Fatal("missing coverage boundaries")
	}
	data, err := Encode(r)
	if err != nil || len(data) > MaxEncodedBytes || data[len(data)-1] != '\n' {
		t.Fatal("bounded encoding failed")
	}
	for _, forbidden := range []string{"commandLine", "privateKey", "remoteHost", "serialNumber", "uninstallString", "macAddress"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("unexpected collection field")
		}
	}
}
func TestSectionBoundsAndMalformedRows(t *testing.T) {
	r := result[Hostname]{rows: []Hostname{{"good"}, {"bad\nname"}, {"another"}}, complete: true}
	s := section("fixed", "fixed", r, 2, func(v Hostname) bool { return textOK(v.Value, true) })
	if s.Complete || !s.Truncated || s.Quality != "limited" || len(s.Rows) != 1 {
		t.Fatal("partial collection mislabeled")
	}
	for _, value := range []string{"", " ", "embedded\x00nul", "bidi\u202Ename", strings.Repeat("a", 257), string([]byte{0xff})} {
		if textOK(value, true) {
			t.Fatal("unsafe text accepted")
		}
	}
	if !textOK("Étude service", true) || !textOK("", false) {
		t.Fatal("valid Unicode or optional field rejected")
	}
}
func TestDeniedAndPartialErrorsDoNotLeak(t *testing.T) {
	raw := errors.New("raw-private-path-and-token")
	for _, err := range []error{raw, os.ErrPermission} {
		r := section("fixed", "fixed", result[Hostname]{err: err}, 1, func(v Hostname) bool { return textOK(v.Value, true) })
		if r.Complete || len(r.Rows) != 0 || r.Quality == "healthy" {
			t.Fatal("failed result mislabeled")
		}
		if errors.Is(err, os.ErrPermission) && r.Quality != "denied" {
			t.Fatal("access denied not preserved")
		}
	}
	p := &fixture{cpuErr: raw, processResult: result[Process]{rows: []Process{{PID: 1, Name: "valid.exe"}}, err: raw, complete: true}}
	r, err := collect(context.Background(), p, noWait)
	if err != nil {
		t.Fatal("partial observation failed")
	}
	if r.CPU.Value != nil || r.Processes.Complete || r.Processes.Quality != "limited" {
		t.Fatal("failed values look complete")
	}
	data, err := Encode(r)
	if err != nil || strings.Contains(string(data), raw.Error()) {
		t.Fatal("native error leaked")
	}
}
func TestCancelledCollectionNeverStartsOrContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &fixture{}
	if _, err := collect(ctx, p, noWait); !errors.Is(err, context.Canceled) || len(p.calls) != 0 {
		t.Fatal("cancelled collection started")
	}
	p = &fixture{}
	if _, err := collect(context.Background(), p, func(context.Context) error { return context.Canceled }); !errors.Is(err, context.Canceled) || len(p.calls) != 2 {
		t.Fatal("sampling cancellation did not stop inventory")
	}
}
func TestInterfaceAddressValidation(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1%private-zone", "not an IP"} {
		if validAddress(InterfaceAddress{Index: 1, Name: "Ethernet", Address: a, PrefixLength: 0}) {
			t.Fatal("excluded address accepted")
		}
	}
	for _, a := range []string{"192.0.2.1", "2001:db8::1", "fe80::1"} {
		if !validAddress(InterfaceAddress{Index: 1, Name: "Ethernet", Address: a, PrefixLength: 24}) {
			t.Fatal("valid local address rejected")
		}
	}
	if validAddress(InterfaceAddress{Index: 1, Name: "Ethernet", Address: "192.0.2.1", PrefixLength: 33}) {
		t.Fatal("bad prefix accepted")
	}
}
func TestEncodeRejectsOversizeDocument(t *testing.T) {
	if _, err := Encode(Report{OS: strings.Repeat("a", MaxEncodedBytes)}); err == nil {
		t.Fatal("oversize output accepted")
	}
}

func TestNilContextRejected(t *testing.T) {
	p := &fixture{}
	if _, err := collect(nil, p, noWait); !errors.Is(err, ErrInvalidInput) || len(p.calls) != 0 {
		t.Fatal("nil context accepted")
	}
}
