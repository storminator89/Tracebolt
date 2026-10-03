package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/model"
)

var nativeFixtureTime = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// These fixtures exercise composition, validation and provenance on any OS.
// They are explicitly NOT evidence that native API calls ran on Windows/macOS.
type windowsFixture struct {
	versionValue                                *windowsVersion
	uptimeValue                                 *time.Duration
	memoryValue                                 *physicalMemory
	volumeValue                                 *volumeCapacity
	versionErr, uptimeErr, memoryErr, volumeErr error
}

func (p windowsFixture) version() (*windowsVersion, error)      { return p.versionValue, p.versionErr }
func (p windowsFixture) uptime() (*time.Duration, error)        { return p.uptimeValue, p.uptimeErr }
func (p windowsFixture) memory() (*physicalMemory, error)       { return p.memoryValue, p.memoryErr }
func (p windowsFixture) systemVolume() (*volumeCapacity, error) { return p.volumeValue, p.volumeErr }

func validWindowsFixture() windowsFixture {
	uptime := 49*time.Hour + 7*time.Minute + 17*time.Second
	return windowsFixture{
		versionValue: &windowsVersion{major: 10, minor: 0, build: 26100},
		uptimeValue:  &uptime,
		memoryValue:  &physicalMemory{total: 32 << 30, available: 8 << 30},
		volumeValue:  &volumeCapacity{total: 800 << 30, available: 280 << 30},
	}
}

type macOSFixture struct {
	product, kernel                                 string
	boot                                            *bootTimeValue
	total                                           *uint64
	fs                                              *filesystemCapacity
	productErr, kernelErr, bootErr, totalErr, fsErr error
}

func (p macOSFixture) productVersion() (string, error)              { return p.product, p.productErr }
func (p macOSFixture) kernelRelease() (string, error)               { return p.kernel, p.kernelErr }
func (p macOSFixture) bootTime() (*bootTimeValue, error)            { return p.boot, p.bootErr }
func (p macOSFixture) totalMemory() (*uint64, error)                { return p.total, p.totalErr }
func (p macOSFixture) rootFilesystem() (*filesystemCapacity, error) { return p.fs, p.fsErr }

func validMacOSFixture() macOSFixture {
	total := uint64(24 << 30)
	boot := nativeFixtureTime.Add(-25*time.Hour - 43*time.Minute)
	return macOSFixture{
		product: "15.6.1", kernel: "24.6.0",
		boot:  &bootTimeValue{seconds: boot.Unix(), microseconds: int64(boot.Nanosecond() / 1000)},
		total: &total,
		fs:    &filesystemCapacity{blocks: 200000, free: 65000, blockSize: 4096},
	}
}

func findEvidence(t *testing.T, d model.Device, id string) model.Evidence {
	t.Helper()
	for _, e := range d.Evidence {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("missing evidence %s", id)
	return model.Evidence{}
}

func findCapability(t *testing.T, d model.Device, id string) model.Capability {
	t.Helper()
	for _, c := range d.Capabilities {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("missing capability %s", id)
	return model.Capability{}
}

func requireMetric(t *testing.T, metric model.Metric, want *float64, quality, source string) {
	t.Helper()
	if metric.Quality != quality || metric.Source != source || metric.Unit != "%" || !metric.CollectedAt.Equal(nativeFixtureTime) {
		t.Errorf("wrong metric provenance: %+v", metric)
	}
	if want == nil {
		if metric.Value != nil {
			t.Errorf("missing metric fabricated value: %v", *metric.Value)
		}
	} else if metric.Value == nil || math.Abs(*metric.Value-*want) > 0.00001 {
		t.Errorf("got metric %+v, want %.5f", metric, *want)
	}
}

func requireNativeContract(t *testing.T, d model.Device, platform, name string) {
	t.Helper()
	if d.ID != "local-"+platform || d.Name != name || d.Source != "local" || d.Platform != platform || d.Synthetic || d.Status != "unknown" || d.IP != nil {
		t.Errorf("native scope invalid: %+v", d)
	}
	if d.Site != "Local machine" || d.Group != "Local observations" || d.AgentVersion != "0.1.0-native-preview" {
		t.Errorf("native fixed labels invalid: %+v", d)
	}
	if !reflect.DeepEqual(d.Tags, []string{"read-only", "local-only", "native-unverified"}) || len(d.Trend) != 0 || len(d.CaseIDs) != 0 {
		t.Errorf("native observation invented history or metadata: %+v", d)
	}
	if !d.LastSeen.Equal(nativeFixtureTime) {
		t.Errorf("observation timestamp changed: %v", d.LastSeen)
	}
	requireMetric(t, d.CPU, nil, "unknown", nativeCPUSource)
	if c := findCapability(t, d, "native_verification"); c.Status != "limited" || !strings.Contains(c.Detail, nativeVerification) {
		t.Errorf("unexecuted native support not disclosed: %+v", c)
	}
	ids := map[string]bool{}
	for _, e := range d.Evidence {
		if ids[e.ID] || e.ID == "" || e.Source == "" || e.Value == "" || !e.CollectedAt.Equal(nativeFixtureTime) || e.Synthetic || !strings.Contains(e.Detail, nativeVerification) {
			t.Errorf("evidence lacks unique ID, provenance or native disclaimer: %+v", e)
		}
		ids[e.ID] = true
		switch e.Quality {
		case "healthy", "unknown", "denied", "stale":
		default:
			t.Errorf("invalid evidence quality %s", e.Quality)
		}
	}
	ids = map[string]bool{}
	for _, c := range d.Capabilities {
		if ids[c.ID] || c.ID == "" || c.Detail == "" {
			t.Errorf("invalid capability: %+v", c)
		}
		ids[c.ID] = true
		switch c.Status {
		case "supported", "limited", "unsupported", "denied":
		default:
			t.Errorf("invalid capability status %s", c.Status)
		}
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"value":null`) {
		t.Error("unknown metric must retain JSON null")
	}
	if strings.Contains(string(encoded), "SECRET-SENTINEL") {
		t.Error("untrusted provider text leaked into observation")
	}
}

func TestWindowsNativeComposition(t *testing.T) {
	d := snapshotWindows(validWindowsFixture(), nativeFixtureTime)
	requireNativeContract(t, d, "windows", "Local Windows")
	if d.OS != "Windows NT 10.0 (build 26100)" || d.Uptime != "2d 1h 7m" {
		t.Errorf("wrong OS/uptime: %s / %s", d.OS, d.Uptime)
	}
	memory, disk := 75.0, 65.0
	requireMetric(t, d.Memory, &memory, "healthy", windowsMemorySource)
	requireMetric(t, d.Disk, &disk, "healthy", windowsDiskSource)
	for _, id := range []string{"os", "uptime", "memory", "disk"} {
		if c := findCapability(t, d, id); c.Status != "supported" {
			t.Errorf("valid sample %s rejected: %+v", id, c)
		}
	}
	if e := findEvidence(t, d, "local-windows-disk"); !strings.Contains(e.Detail, "matching caller-total and caller-available") {
		t.Error("disk quota scope omitted")
	}
}

func TestMacOSNativeComposition(t *testing.T) {
	d := snapshotMacOS(validMacOSFixture(), nativeFixtureTime)
	requireNativeContract(t, d, "macos", "Local macOS")
	if d.OS != "macOS 15.6.1" || d.Uptime != "1d 1h 43m" {
		t.Errorf("wrong OS/uptime: %s / %s", d.OS, d.Uptime)
	}
	disk := 67.5
	requireMetric(t, d.Disk, &disk, "healthy", macDiskSource)
	requireMetric(t, d.Memory, nil, "unknown", macMemorySource)
	if c := findCapability(t, d, "memory"); c.Status != "unsupported" {
		t.Errorf("RAM capacity used as utilization: %+v", c)
	}
	if e := findEvidence(t, d, "local-macos-memory-capacity"); e.Quality != "healthy" || e.Value != "25769803776 bytes" || e.Source != macTotalSource {
		t.Errorf("capacity missing: %+v", e)
	}
	if e := findEvidence(t, d, "local-macos-kernel"); e.Value != "Darwin 24.6.0" || e.Source != macKernelSource {
		t.Errorf("kernel provenance lost: %+v", e)
	}
}

func TestWindowsMissingAndFailedReads(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		quality string
	}{
		{"null", nil, "unknown"},
		{"failed", errors.New("SECRET-SENTINEL"), "unknown"},
		{"denied", fmt.Errorf("SECRET-SENTINEL: %w", os.ErrPermission), "denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := windowsFixture{versionErr: test.err, uptimeErr: test.err, memoryErr: test.err, volumeErr: test.err}
			d := snapshotWindows(p, nativeFixtureTime)
			requireNativeContract(t, d, "windows", "Local Windows")
			requireMetric(t, d.Memory, nil, test.quality, windowsMemorySource)
			requireMetric(t, d.Disk, nil, test.quality, windowsDiskSource)
			if d.Uptime != "Unknown" || d.OS != "Windows (version unavailable)" {
				t.Errorf("missing strings fabricated: %+v", d)
			}
			for _, id := range []string{"os", "uptime", "memory", "disk"} {
				if c := findCapability(t, d, id); c.Status != capabilityStatus(test.quality) {
					t.Errorf("failure quality lost: %+v", c)
				}
				if e := findEvidence(t, d, "local-windows-"+id); e.Quality != test.quality {
					t.Errorf("failure evidence quality lost: %+v", e)
				}
			}
		})
	}
}

func TestMacOSMissingAndFailedReads(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		quality string
	}{
		{"null", nil, "unknown"},
		{"failed", errors.New("SECRET-SENTINEL"), "unknown"},
		{"denied", fmt.Errorf("SECRET-SENTINEL: %w", os.ErrPermission), "denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := macOSFixture{productErr: test.err, kernelErr: test.err, bootErr: test.err, totalErr: test.err, fsErr: test.err}
			d := snapshotMacOS(p, nativeFixtureTime)
			requireNativeContract(t, d, "macos", "Local macOS")
			requireMetric(t, d.Disk, nil, test.quality, macDiskSource)
			requireMetric(t, d.Memory, nil, "unknown", macMemorySource)
			if d.Uptime != "Unknown" || d.OS != "macOS (version unavailable)" {
				t.Errorf("missing strings fabricated: %+v", d)
			}
			for _, id := range []string{"os", "kernel", "uptime", "memory-capacity", "disk"} {
				if e := findEvidence(t, d, "local-macos-"+id); e.Quality != test.quality {
					t.Errorf("failure evidence quality lost: %+v", e)
				}
			}
		})
	}
}

func TestNativeErrorsDiscardReturnedValues(t *testing.T) {
	denied := fmt.Errorf("SECRET-SENTINEL: %w", os.ErrPermission)
	w := validWindowsFixture()
	w.versionErr, w.uptimeErr, w.memoryErr, w.volumeErr = denied, denied, denied, denied
	wd := snapshotWindows(w, nativeFixtureTime)
	requireNativeContract(t, wd, "windows", "Local Windows")
	requireMetric(t, wd.Memory, nil, "denied", windowsMemorySource)
	requireMetric(t, wd.Disk, nil, "denied", windowsDiskSource)
	if wd.OS != "Windows (version unavailable)" || wd.Uptime != "Unknown" {
		t.Error("Windows retained values from a failed call")
	}
	m := validMacOSFixture()
	m.productErr, m.kernelErr, m.bootErr, m.totalErr, m.fsErr = denied, denied, denied, denied, denied
	md := snapshotMacOS(m, nativeFixtureTime)
	requireNativeContract(t, md, "macos", "Local macOS")
	requireMetric(t, md.Disk, nil, "denied", macDiskSource)
	for _, id := range []string{"os", "kernel", "uptime", "memory-capacity"} {
		e := findEvidence(t, md, "local-macos-"+id)
		if e.Quality != "denied" {
			t.Errorf("macOS retained values from a failed call: %+v", e)
		}
	}
}

func TestWindowsMalformedReads(t *testing.T) {
	negative := -time.Millisecond
	p := windowsFixture{versionValue: &windowsVersion{}, uptimeValue: &negative,
		memoryValue: &physicalMemory{total: 10, available: 11}, volumeValue: &volumeCapacity{total: 0, available: 1}}
	d := snapshotWindows(p, nativeFixtureTime)
	requireNativeContract(t, d, "windows", "Local Windows")
	requireMetric(t, d.Memory, nil, "unknown", windowsMemorySource)
	requireMetric(t, d.Disk, nil, "unknown", windowsDiskSource)
	if d.OS != "Windows (version unavailable)" || d.Uptime != "Unknown" {
		t.Error("malformed Windows values accepted")
	}
}

func TestMacOSMalformedReads(t *testing.T) {
	zero := uint64(0)
	p := macOSFixture{product: "SECRET-SENTINEL\n15.6.1", kernel: "Darwin SECRET-SENTINEL", total: &zero,
		boot: &bootTimeValue{seconds: nativeFixtureTime.Unix() + 1}, fs: &filesystemCapacity{blocks: 10, free: 11, blockSize: 4096}}
	d := snapshotMacOS(p, nativeFixtureTime)
	requireNativeContract(t, d, "macos", "Local macOS")
	requireMetric(t, d.Disk, nil, "unknown", macDiskSource)
	for _, id := range []string{"os", "kernel", "uptime", "memory-capacity"} {
		if e := findEvidence(t, d, "local-macos-"+id); e.Quality != "unknown" {
			t.Errorf("malformed macOS value accepted: %+v", e)
		}
	}
}

func TestNativeCapacityBounds(t *testing.T) {
	for _, pair := range [][2]uint64{{0, 0}, {0, 1}, {100, 101}, {math.MaxUint64, 0}, {100, math.MaxUint64}} {
		if _, ok := nativeCapacityPercent(pair[0], pair[1]); ok {
			t.Errorf("invalid capacity accepted: %v", pair)
		}
	}
	for _, test := range []struct {
		total, free uint64
		want        float64
	}{{100, 100, 0}, {100, 0, 100}, {16384, 4096, 75}, {math.MaxInt64, 0, 100}} {
		value, ok := nativeCapacityPercent(test.total, test.free)
		if !ok || value != test.want {
			t.Errorf("valid capacity rejected: %+v -> %v %t", test, value, ok)
		}
	}
	for _, total := range []uint64{0, math.MaxUint64} {
		if value, quality := nativeByteCapacity(&total, nil); value != "Unavailable" || quality != "unknown" {
			t.Errorf("invalid capacity evidence: %s %s", value, quality)
		}
	}
	for _, fs := range []filesystemCapacity{{blocks: 10, free: 5}, {blocks: math.MaxUint64, blockSize: 4096}, {blocks: 10, free: math.MaxUint64, blockSize: 4096}, {blocks: 10, blockSize: math.MaxUint32}, {blocks: math.MaxInt64, blockSize: 4096}} {
		p := validMacOSFixture()
		p.fs = &fs
		requireMetric(t, snapshotMacOS(p, nativeFixtureTime).Disk, nil, "unknown", macDiskSource)
	}
}

func TestNativeUptimeBounds(t *testing.T) {
	for _, test := range []struct {
		value time.Duration
		valid bool
	}{{0, true}, {maxNativeUptime, true}, {-1, false}, {maxNativeUptime + 1, false}, {time.Duration(math.MaxInt64), false}} {
		if got := validNativeUptime(test.value); got != test.valid {
			t.Errorf("uptime %s validity %t", test.value, got)
		}
	}
	for _, boot := range []*bootTimeValue{nil, {}, {seconds: -1}, {seconds: nativeFixtureTime.Unix() + 1}, {seconds: nativeFixtureTime.Unix(), microseconds: -1}, {seconds: nativeFixtureTime.Unix(), microseconds: 1000000}, {seconds: math.MaxInt64}, {seconds: 1}} {
		if _, ok := macOSUptime(boot, nativeFixtureTime); ok {
			t.Errorf("invalid boot time accepted: %+v", boot)
		}
	}
	for _, seconds := range []int64{0, 60, int64(maxNativeUptime / time.Second)} {
		boot := &bootTimeValue{seconds: nativeFixtureTime.Unix() - seconds}
		if duration, ok := macOSUptime(boot, nativeFixtureTime); !ok || duration != time.Duration(seconds)*time.Second {
			t.Errorf("valid boot time rejected: %+v -> %s %t", boot, duration, ok)
		}
	}
	boot := &bootTimeValue{seconds: nativeFixtureTime.Unix() - 1, microseconds: 750000}
	if duration, ok := macOSUptime(boot, nativeFixtureTime); !ok || duration != 250*time.Millisecond {
		t.Errorf("timeval microseconds misinterpreted: %s %t", duration, ok)
	}
}

func TestNativeVersionValidation(t *testing.T) {
	for _, value := range []string{"15.6.1", "24.6.0", "10.15", "26.1.0.1"} {
		if !validNativeVersion(value) {
			t.Errorf("valid version %q rejected", value)
		}
	}
	for _, value := range []string{"", "15", "15.", ".6", "0.0", "15..6", "15.6.1.2.3", "15.6\x00", "15.6\n", " 15.6", "-15.6", "15.6 SECRET-SENTINEL", strings.Repeat("1", 33) + ".1"} {
		if validNativeVersion(value) {
			t.Errorf("invalid version %q accepted", value)
		}
	}
}

type volumeFixture struct {
	directory                 string
	directoryErr, capacityErr error
	fixed                     bool
	value                     *volumeCapacity
	calls                     []string
}

func (p *volumeFixture) systemDirectory() (string, error) {
	p.calls = append(p.calls, "directory")
	return p.directory, p.directoryErr
}
func (p *volumeFixture) fixedDrive(root string) bool {
	p.calls = append(p.calls, "fixed:"+root)
	return p.fixed
}
func (p *volumeFixture) capacity(root string) (*volumeCapacity, error) {
	p.calls = append(p.calls, "capacity:"+root)
	return p.value, p.capacityErr
}

func TestWindowsRootSelectionAndReadBoundary(t *testing.T) {
	for _, test := range []struct{ path, root string }{{`C:\Windows\System32`, `C:\`}, {`D:\Windows\System32`, `D:\`}, {`c:\`, `c:\`}} {
		if root, ok := windowsSystemDriveRoot(test.path); !ok || root != test.root {
			t.Errorf("root %q -> %q %t", test.path, root, ok)
		}
		p := &volumeFixture{directory: test.path, fixed: true, value: &volumeCapacity{total: 100, available: 25}}
		value, err := queryWindowsSystemVolume(p)
		if err != nil || value != p.value || !reflect.DeepEqual(p.calls, []string{"directory", "fixed:" + test.root, "capacity:" + test.root}) {
			t.Errorf("wrong root query sequence: %+v %v", p.calls, err)
		}
	}
	for _, path := range []string{"", `C:Windows`, `C:/Windows`, `\\server\share`, `\\?\C:\Windows`, `\\.\C:\Windows`, `%SystemRoot%`, `\Windows`, `/Windows`, `1:\Windows`, `C:\..\Windows`, `C:\.\Windows`, "C:\\Windows\x00", `C:\Windows:other`, `C:\Windows/path`} {
		if root, ok := windowsSystemDriveRoot(path); ok {
			t.Errorf("unsafe path %q -> %q", path, root)
		}
		p := &volumeFixture{directory: path, fixed: true}
		if _, err := queryWindowsSystemVolume(p); err == nil || !reflect.DeepEqual(p.calls, []string{"directory"}) {
			t.Errorf("invalid root reached native disk call: %q %v", path, p.calls)
		}
	}
	p := &volumeFixture{directory: `Z:\Windows\System32`, fixed: false}
	if _, err := queryWindowsSystemVolume(p); err == nil || !reflect.DeepEqual(p.calls, []string{"directory", `fixed:Z:\`}) {
		t.Errorf("non-local drive reached capacity query: %v", p.calls)
	}
	p = &volumeFixture{directory: `C:\Windows\System32`, directoryErr: os.ErrPermission, fixed: true}
	if _, err := queryWindowsSystemVolume(p); !errors.Is(err, os.ErrPermission) || !reflect.DeepEqual(p.calls, []string{"directory"}) {
		t.Errorf("directory denial lost or query continued: %v %v", p.calls, err)
	}
	p = &volumeFixture{directory: `C:\Windows\System32`, fixed: true, capacityErr: os.ErrPermission}
	if _, err := queryWindowsSystemVolume(p); !errors.Is(err, os.ErrPermission) {
		t.Errorf("capacity denial lost: %v", err)
	}
}

func TestNativeSnapshotsEncodeSupportBundle(t *testing.T) {
	denied := fmt.Errorf("SECRET-SENTINEL: %w", os.ErrPermission)
	for _, test := range []struct {
		name   string
		device model.Device
	}{
		{"windows-valid", snapshotWindows(validWindowsFixture(), nativeFixtureTime)},
		{"windows-unavailable", snapshotWindows(windowsFixture{}, nativeFixtureTime)},
		{"windows-denied", snapshotWindows(windowsFixture{versionErr: denied, uptimeErr: denied, memoryErr: denied, volumeErr: denied}, nativeFixtureTime)},
		{"macos-valid", snapshotMacOS(validMacOSFixture(), nativeFixtureTime)},
		{"macos-unavailable", snapshotMacOS(macOSFixture{}, nativeFixtureTime)},
		{"macos-denied", snapshotMacOS(macOSFixture{productErr: denied, kernelErr: denied, bootErr: denied, totalErr: denied, fsErr: denied}, nativeFixtureTime)},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := bundle.Encode(test.device)
			if err != nil {
				t.Fatalf("native composition rejected by bundle: %v", err)
			}
			if len(encoded) > bundle.MaxBytes || strings.Contains(string(encoded), "SECRET-SENTINEL") {
				t.Error("bundle exceeded bound or leaked provider detail")
			}
			var decoded bundle.Bundle
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.Observation, test.device) {
				t.Errorf("native observation changed in bundle round trip")
			}
			if decoded.Observation.Status != "unknown" || !strings.Contains(string(encoded), nativeVerification) {
				t.Error("bundle lost limitations")
			}
		})
	}
}
