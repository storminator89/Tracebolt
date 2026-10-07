package windowsmanaged

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
)

const fixtureGeneration = "sample_0123456789abcdef0123456789abcdef"

func fixtureSection[T any](rows []T) windowsinventory.Section[T] {
	return windowsinventory.Section[T]{Source: "Injected fixture source", Scope: "Injected scoped observation; not a native acceptance claim", Quality: "healthy", Complete: true, Rows: rows}
}

func fixtureReport() windowsinventory.Report {
	at := time.Date(2026, 10, 7, 12, 0, 0, 123456000, time.UTC)
	metric := func(value float64, offset time.Duration) model.Metric {
		return model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Injected fixture metric", CollectedAt: at.Add(offset)}
	}
	return windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at,
		NativeVerification: "installed-service-and-enrollment-unverified", OS: "Windows NT 10.0 (build 26100)", Uptime: "1d 0h 0m",
		CPU: metric(37.5, 250*time.Millisecond), Memory: metric(62.25, -time.Millisecond), Disk: metric(48.5, -time.Millisecond),
		Hostname:  fixtureSection([]Hostname{{Value: "FIXTURE-PC"}}),
		Processes: fixtureSection([]Process{{PID: 23, ParentPID: 4, Name: "example.exe", Threads: 3}, {PID: 0, Name: "[System Process]"}}),
		Services:  fixtureSection([]Service{{Name: "ExampleService", DisplayName: "Example service", State: "running", PID: 23}}),
		Software:  fixtureSection([]Software{{Name: "Example software", Version: "1.2.3", Publisher: "Example publisher", RegistryView: "64"}}),
		Network:   fixtureSection([]InterfaceAddress{{Index: 1, Name: "Ethernet", Address: "192.0.2.10", PrefixLength: 24}, {Index: 1, Name: "Ethernet", Address: "2001:db8::10", PrefixLength: 64}})}
}

func fixtureSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s, _, err := FromReport(fixtureReport(), fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSameReportPreservesTimesMetricsAndBundleContract(t *testing.T) {
	r := fixtureReport()
	before, _ := json.Marshal(r)
	s, d, err := FromReport(r, fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != SchemaVersion || s.CollectionProfile != CollectionProfile || s.GenerationID != fixtureGeneration || !s.CollectedAt.Equal(r.CollectedAt) {
		t.Fatal("transport identity or original capture time changed")
	}
	if !reflect.DeepEqual(d.CPU, r.CPU) || !reflect.DeepEqual(d.Memory, r.Memory) || !reflect.DeepEqual(d.Disk, r.Disk) || !d.LastSeen.Equal(r.CPU.CollectedAt) {
		t.Fatal("shared-chart metrics or their capture times changed")
	}
	if err := bundle.ValidateObservation(d); err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Encode(d)
	if err != nil || len(b) > 16<<10 {
		t.Fatal("device does not fit shared observation frame")
	}
	if s.Processes.Rows[0].PID != 0 || s.Processes.ObservedCount != 2 || !s.Processes.CountExact || !s.Processes.Complete || s.Processes.Truncated {
		t.Fatal("scoped complete process observation changed")
	}
	if d.Name != "Local Windows" || d.IP != nil || bytes.Contains(b, []byte("FIXTURE-PC")) || bytes.Contains(b, []byte("192.0.2.10")) {
		t.Fatal("explicit inventory identifiers escaped into basic observation")
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("adapter mutated input report")
	}
	s.Processes.Rows[0].Name = "changed.exe"
	*d.CPU.Value = 0
	if r.Processes.Rows[1].Name != "[System Process]" || *r.CPU.Value != 37.5 {
		t.Fatal("adapter aliases caller-owned data")
	}
}

func TestNativePartialDeniedUnavailableAndTruncatedRemainHonest(t *testing.T) {
	r := fixtureReport()
	r.Processes.Quality, r.Processes.Complete = "limited", false
	r.Services.Quality, r.Services.Complete, r.Services.Rows = "denied", false, nil
	r.Software.Quality, r.Software.Complete, r.Software.Rows = "unknown", false, nil
	r.Network.Quality, r.Network.Complete, r.Network.Truncated = "limited", false, true
	r.CPU.Quality, r.CPU.Value = "denied", nil
	s, d, err := FromReport(r, fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if s.Processes.Quality != QualityPartial || s.Processes.Complete || s.Processes.CountExact || s.Processes.Truncated || s.Processes.ObservedCount != 2 {
		t.Fatal("partial source became complete or exact")
	}
	if s.Services.Quality != QualityDenied || s.Services.Rows == nil || s.Services.ObservedCount != 0 || s.Services.CountExact || s.Services.Complete {
		t.Fatal("denied source became an empty successful observation")
	}
	if s.Software.Quality != QualityUnavailable || s.Software.Rows == nil || s.Software.Complete || s.Software.CountExact {
		t.Fatal("unavailable source became an empty successful observation")
	}
	if s.Network.Quality != QualityPartial || !s.Network.Truncated || s.Network.CountExact || s.Network.ObservedCount != 2 || len(s.Network.Rows) != 2 {
		t.Fatal("upstream row limit concealed")
	}
	if d.CPU.Value != nil || d.CPU.Quality != "denied" || bundle.ValidateObservation(d) != nil {
		t.Fatal("unavailable chart metric fabricated")
	}
	if _, err := Encode(s); err != nil {
		t.Fatal(err)
	}
}

func TestRecordCapsPreserveOriginalCountAndTime(t *testing.T) {
	r := fixtureReport()
	r.Processes.Rows = nil
	for i := windowsinventory.MaxProcesses; i > 0; i-- {
		r.Processes.Rows = append(r.Processes.Rows, Process{PID: uint32(i), Name: "p.exe"})
	}
	s, _, err := FromReport(r, fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Processes.Rows) != MaxProcessRows || s.Processes.ObservedCount != windowsinventory.MaxProcesses || !s.Processes.CountExact || s.Processes.Complete || !s.Processes.Truncated || s.Processes.Quality != QualityPartial {
		t.Fatal("transport cap changed native count or completeness")
	}
	if s.Processes.Rows[0].PID != 1 || s.Processes.Rows[MaxProcessRows-1].PID != MaxProcessRows || !s.CollectedAt.Equal(r.CollectedAt) {
		t.Fatal("trim is not a deterministic sorted prefix with original time")
	}
}

func largeReport() windowsinventory.Report {
	r := fixtureReport()
	r.Processes.Rows, r.Services.Rows, r.Software.Rows, r.Network.Rows = nil, nil, nil, nil
	for i := 0; i < MaxProcessRows; i++ {
		name := fmt.Sprintf("%03d", i) + strings.Repeat("<", 250)
		r.Processes.Rows = append(r.Processes.Rows, Process{PID: uint32(i), Name: name})
		r.Services.Rows = append(r.Services.Rows, Service{Name: name, DisplayName: strings.Repeat("&", 256), State: "running"})
		r.Software.Rows = append(r.Software.Rows, Software{Name: name, Version: strings.Repeat(">", 256), Publisher: strings.Repeat("&", 256), RegistryView: "64"})
		if i < MaxNetworkRows {
			r.Network.Rows = append(r.Network.Rows, InterfaceAddress{Index: i + 1, Name: name, Address: fmt.Sprintf("192.0.2.%d", i+1), PrefixLength: 24})
		}
	}
	return r
}

func TestEncodedByteLimitIncludesEscapesAndTrimsDeterministically(t *testing.T) {
	r := largeReport()
	s, _, err := FromReport(r, fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(s)
	if err != nil || len(b) > MaxSnapshotBytes {
		t.Fatal("snapshot exceeds frame allowance")
	}
	for _, section := range []struct {
		quality                    string
		complete, truncated, exact bool
		count                      uint32
		rows                       int
	}{
		{s.Processes.Quality, s.Processes.Complete, s.Processes.Truncated, s.Processes.CountExact, s.Processes.ObservedCount, len(s.Processes.Rows)},
		{s.Services.Quality, s.Services.Complete, s.Services.Truncated, s.Services.CountExact, s.Services.ObservedCount, len(s.Services.Rows)},
		{s.Software.Quality, s.Software.Complete, s.Software.Truncated, s.Software.CountExact, s.Software.ObservedCount, len(s.Software.Rows)},
		{s.Network.Quality, s.Network.Complete, s.Network.Truncated, s.Network.CountExact, s.Network.ObservedCount, len(s.Network.Rows)},
	} {
		if section.complete || !section.truncated || !section.exact || section.quality != QualityPartial || int(section.count) <= section.rows || section.rows == 0 {
			t.Fatal("byte-limited section lacks honest retained/native coverage")
		}
	}
	// Reordering the supplied rows must not change the transport representation.
	reverse := func(n int, swap func(int, int)) {
		for i := 0; i < n/2; i++ {
			swap(i, n-1-i)
		}
	}
	reverse(len(r.Processes.Rows), func(i, j int) { r.Processes.Rows[i], r.Processes.Rows[j] = r.Processes.Rows[j], r.Processes.Rows[i] })
	reverse(len(r.Services.Rows), func(i, j int) { r.Services.Rows[i], r.Services.Rows[j] = r.Services.Rows[j], r.Services.Rows[i] })
	reverse(len(r.Software.Rows), func(i, j int) { r.Software.Rows[i], r.Software.Rows[j] = r.Software.Rows[j], r.Software.Rows[i] })
	reverse(len(r.Network.Rows), func(i, j int) { r.Network.Rows[i], r.Network.Rows[j] = r.Network.Rows[j], r.Network.Rows[i] })
	again, _, err := FromReport(r, fixtureGeneration)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Encode(again)
	if !bytes.Equal(b, b2) {
		t.Fatal("trim depended on source enumeration order")
	}
	decoded, err := Decode(b)
	if err != nil || !reflect.DeepEqual(decoded, s) {
		t.Fatal("bounded snapshot did not strictly round trip")
	}
}

func TestValidateRejectsInconsistentSchemaAndRows(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"schema", func(s *Snapshot) { s.SchemaVersion = windowsinventory.Schema }},
		{"profile", func(s *Snapshot) { s.CollectionProfile = "complete-v3" }},
		{"uppercase generation", func(s *Snapshot) { s.GenerationID = "sample_0123456789ABCDEF0123456789ABCDEF" }},
		{"zero time", func(s *Snapshot) { s.CollectedAt = time.Time{} }},
		{"non UTC time", func(s *Snapshot) { s.CollectedAt = s.CollectedAt.In(time.FixedZone("offset", 3600)) }},
		{"pre epoch", func(s *Snapshot) { s.CollectedAt = time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"nil rows", func(s *Snapshot) { s.Processes.Rows = nil }},
		{"empty complete hostname", func(s *Snapshot) { s.Hostname.Rows = []Hostname{}; s.Hostname.ObservedCount = 0 }},
		{"count below rows", func(s *Snapshot) { s.Processes.ObservedCount = 1 }},
		{"count over source cap", func(s *Snapshot) { s.Processes.ObservedCount = windowsinventory.MaxProcesses + 1 }},
		{"unacknowledged omitted rows", func(s *Snapshot) { s.Processes.ObservedCount++ }},
		{"healthy partial", func(s *Snapshot) { s.Processes.Complete = false }},
		{"healthy nonexact", func(s *Snapshot) { s.Processes.CountExact = false }},
		{"healthy truncated", func(s *Snapshot) { s.Processes.Truncated = true }},
		{"denied rows", func(s *Snapshot) {
			s.Processes.Quality = QualityDenied
			s.Processes.Complete = false
			s.Processes.CountExact = false
		}},
		{"partial claims exact complete count", func(s *Snapshot) { s.Processes.Quality = QualityPartial; s.Processes.Complete = false }},
		{"unknown quality", func(s *Snapshot) { s.Processes.Quality = "unknown" }},
		{"process path", func(s *Snapshot) { s.Processes.Rows[0].Name = `C:\private\process.exe` }},
		{"bad service state", func(s *Snapshot) { s.Services.Rows[0].State = "active" }},
		{"bad registry view", func(s *Snapshot) { s.Software.Rows[0].RegistryView = "user" }},
		{"control text", func(s *Snapshot) { s.Software.Rows[0].Name = "private\ntext" }},
		{"oversize text", func(s *Snapshot) { s.Software.Rows[0].Name = strings.Repeat("x", 257) }},
		{"invalid UTF8", func(s *Snapshot) { s.Hostname.Rows[0].Value = string([]byte{0xff}) }},
		{"source controls", func(s *Snapshot) { s.Network.Source = "injected\x00" }},
		{"missing scope", func(s *Snapshot) { s.Network.Scope = "" }},
		{"loopback", func(s *Snapshot) { s.Network.Rows[0].Address = "127.0.0.1" }},
		{"unspecified", func(s *Snapshot) { s.Network.Rows[0].Address = "0.0.0.0" }},
		{"multicast", func(s *Snapshot) { s.Network.Rows[0].Address = "224.0.0.1" }},
		{"zone", func(s *Snapshot) { s.Network.Rows[0].Address = "fe80::1%private" }},
		{"noncanonical address", func(s *Snapshot) { s.Network.Rows[1].Address = "2001:DB8::10" }},
		{"prefix", func(s *Snapshot) { s.Network.Rows[0].PrefixLength = 33 }},
		{"index", func(s *Snapshot) { s.Network.Rows[0].Index = -1 }},
		{"row cap", func(s *Snapshot) {
			for len(s.Processes.Rows) <= MaxProcessRows {
				s.Processes.Rows = append(s.Processes.Rows, Process{Name: "p.exe"})
			}
			s.Processes.ObservedCount = uint32(len(s.Processes.Rows))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fixtureSnapshot(t)
			tt.mutate(&s)
			if Validate(s) == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestDecodeRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	b, err := Encode(fixtureSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	base := string(b)
	tests := map[string]string{
		"duplicate root":          strings.Replace(base, `"schemaVersion":`, `"schemaVersion":"ignored","schemaVersion":`, 1),
		"duplicate nested":        strings.Replace(base, `"observedCount":2`, `"observedCount":2,"observedCount":2`, 1),
		"duplicate escaped key":   strings.Replace(base, `"observedCount":2`, `"observedCount":2,"observed\u0043ount":2`, 1),
		"duplicate row":           strings.Replace(base, `"pid":0`, `"pid":0,"pid":0`, 1),
		"unknown root":            strings.Replace(base, `"schemaVersion":`, `"events":[],"schemaVersion":`, 1),
		"unknown row":             strings.Replace(base, `"pid":0`, `"owner":"someone","pid":0`, 1),
		"missing boolean":         strings.Replace(base, `"complete":true,`, ``, 1),
		"wrong case":              strings.Replace(base, `"complete":`, `"Complete":`, 1),
		"null rows":               strings.Replace(base, `"rows":[{"value":"FIXTURE-PC"}]`, `"rows":null`, 1),
		"null section":            strings.Replace(base, `"hostname":{`, `"hostname":null,"ignored":{`, 1),
		"null numeric":            strings.Replace(base, `"pid":0`, `"pid":null`, 1),
		"decimal":                 strings.Replace(base, `"pid":0`, `"pid":0.0`, 1),
		"exponent":                strings.Replace(base, `"pid":0`, `"pid":0e0`, 1),
		"negative":                strings.Replace(base, `"pid":0`, `"pid":-1`, 1),
		"overflow":                strings.Replace(base, `"pid":0`, `"pid":4294967296`, 1),
		"quoted integer":          strings.Replace(base, `"pid":0`, `"pid":"0"`, 1),
		"offset timestamp":        strings.Replace(base, `123456Z`, `123456+00:00`, 1),
		"subnanosecond timestamp": strings.Replace(base, `123456Z`, `123456789111Z`, 1),
		"invalid timestamp":       strings.Replace(base, `2026-10-07`, `2026-13-07`, 1),
		"unpaired surrogate":      strings.Replace(base, `FIXTURE-PC`, `\ud800`, 1),
		"trailing object":         base + `{}`,
		"trailing garbage":        base + `garbage`,
		"empty":                   "",
		"invalid UTF8":            strings.Replace(base, "FIXTURE-PC", string([]byte{0xff}), 1),
		"deep nesting":            strings.Repeat("[", 20) + strings.Repeat("]", 20),
		"overlimit":               strings.Repeat(" ", MaxSnapshotBytes+1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(raw)); err == nil {
				t.Fatal("malformed JSON accepted")
			}
		})
	}
}

func TestAdapterRejectsMalformedSourceWithoutCollection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*windowsinventory.Report)
	}{
		{"wrong platform", func(r *windowsinventory.Report) { r.Platform = "linux" }},
		{"wrong schema", func(r *windowsinventory.Report) { r.Schema = SchemaVersion }},
		{"zero metric time", func(r *windowsinventory.Report) { r.CPU.CollectedAt = time.Time{} }},
		{"healthy nil metric", func(r *windowsinventory.Report) { r.CPU.Value = nil }},
		{"denied metric value", func(r *windowsinventory.Report) { r.CPU.Quality = "denied" }},
		{"NaN metric", func(r *windowsinventory.Report) { *r.CPU.Value = math.NaN() }},
		{"out of range metric", func(r *windowsinventory.Report) { *r.CPU.Value = 101 }},
		{"wrong metric unit", func(r *windowsinventory.Report) { r.CPU.Unit = "bytes" }},
		{"bad metric source", func(r *windowsinventory.Report) { r.CPU.Source = "unsafe\nsource" }},
		{"incomplete healthy source", func(r *windowsinventory.Report) { r.Processes.Complete = false }},
		{"denied with source rows", func(r *windowsinventory.Report) { r.Services.Quality = "denied"; r.Services.Complete = false }},
		{"source overlimit", func(r *windowsinventory.Report) { r.Software.Rows = make([]Software, windowsinventory.MaxSoftware+1) }},
		{"source unsafe row", func(r *windowsinventory.Report) { r.Software.Rows[0].Publisher = "private\x00value" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureReport()
			tt.mutate(&r)
			if _, _, err := FromReport(r, fixtureGeneration); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
	if _, _, err := FromReport(fixtureReport(), "sample_invalid"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("invalid generation accepted")
	}
	// None of these calls can reach a host collector, including on Windows.
	if _, _, err := Collect(nil, fixtureGeneration); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context accepted")
	}
	if _, _, err := Collect(context.Background(), "invalid"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("invalid generation collected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Collect(ctx, fixtureGeneration); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collection started")
	}
}
