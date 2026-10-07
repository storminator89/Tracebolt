package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
)

func windowsConfig(c Config) Config {
	c.SchemaVersion, c.CollectionProfile, c.Profile = WindowsInventoryConfigVersion, enrollmentcrypto.CollectionProfileWindowsInventory, "tls"
	return c
}
func syntheticWindowsReport(at time.Time) windowsinventory.Report {
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Synthetic fixture", CollectedAt: at}
	return windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Windows fixture", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Fixture source", Scope: "Fixture scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "fixture-host"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Fixture source", Scope: "Fixture scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 7, Name: "fixture.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Fixture source", Scope: "Fixture scope", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Fixture source", Scope: "Fixture scope", Quality: "unknown", Rows: []windowsinventory.Software{}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Fixture source", Scope: "Fixture scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 1, Name: "Fixture interface", Address: "192.0.2.9", PrefixLength: 24}}}}
}
func windowsSource(_ context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
	return windowsmanaged.FromReport(syntheticWindowsReport(time.Now().UTC()), generation)
}

func TestWindowsInventoryFrameComesFromOneConsentedReport(t *testing.T) {
	calls := 0
	collect := func(ctx context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
		calls++
		r := syntheticWindowsReport(time.Now().UTC().Add(-time.Second))
		r.CPU.CollectedAt = r.CollectedAt.Add(250 * time.Millisecond)
		return windowsmanaged.FromReport(r, generation)
	}
	f, raw, err := collectFrameWithDependencies(context.Background(), windowsConfig(Config{}), 1, nil, nil, nil, collect)
	if err != nil || calls != 1 || f.WindowsInventory == nil || f.Operational != nil || f.Packages != nil || f.SchemaVersion != FrameWindowsInventoryVersion {
		t.Fatal("Windows frame invoked wrong scope", err)
	}
	if !f.Observation.Observation.LastSeen.Equal(f.Observation.Observation.CPU.CollectedAt) || f.WindowsInventory.CollectedAt.After(f.Observation.Observation.LastSeen) {
		t.Fatal("interval timing lost")
	}
	if len(raw) > MaxFrameBytes || bytes.Contains(raw, []byte(`"operational"`)) || bytes.Contains(raw, []byte(`"packages"`)) {
		t.Fatal("wrong frame budget or scope")
	}
	if _, err := decodeFrameForConfig(raw, 1, windowsConfig(Config{})); err != nil {
		t.Fatal(err)
	}
	if _, err := lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal("manager rejects fresh Windows frame", err)
	}
	for _, old := range []Config{{SchemaVersion: ConfigVersion}, {SchemaVersion: GuidedConfigVersion}, {SchemaVersion: OperationalConfigVersion, CollectionProfile: enrollmentcrypto.CollectionProfileOperational}, {SchemaVersion: PackageConfigVersion, CollectionProfile: enrollmentcrypto.CollectionProfilePackages}, {SchemaVersion: CompleteConfigVersion, CollectionProfile: enrollmentcrypto.CollectionProfileComplete}} {
		if _, err := decodeFrameForConfig(raw, 1, old); err == nil {
			t.Fatal("older profile accepted Windows pending")
		}
	}
}

func TestWindowsInventoryPendingStrictShapeAndBounds(t *testing.T) {
	c := windowsConfig(Config{})
	f, raw, err := collectWindowsFrame(context.Background(), c, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func([]byte) []byte{
		"missing-count": func(b []byte) []byte { return bytes.Replace(b, []byte(`"countExact":true,`), nil, 1) },
		"duplicate-count": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"countExact":true`), []byte(`"countExact":true,"countExact":true`), 1)
		},
		"unknown-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"windowsInventory":{`), []byte(`"windowsInventory":{"trusted":true,`), 1)
		},
		"basic-missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"synthetic":false,`), nil, 1) },
		"basic-unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"observation":{"id"`), []byte(`"observation":{"hostname":"private","id"`), 1)
		},
		"null-rows":        func(b []byte) []byte { return bytes.Replace(b, []byte(`"rows":[]`), []byte(`"rows":null`), 1) },
		"malformed-string": func(b []byte) []byte { return bytes.Replace(b, []byte(`"fixture-host"`), []byte(`"\ud800"`), 1) },
	} {
		bad := alter(bytes.Clone(raw))
		if bytes.Equal(bad, raw) {
			t.Fatal("ineffective fixture", name)
		}
		if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
			t.Fatal("invalid pending accepted", name)
		}
	}
	for name, cap := range map[string]int{"observation": MaxWindowsObservationBytes, "windowsInventory": windowsmanaged.MaxSnapshotBytes} {
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		needle := []byte(`"` + name + `":{`)
		padded := bytes.Replace(raw, needle, append(bytes.Clone(needle), bytes.Repeat([]byte(" "), cap-len(fields[name]))...), 1)
		if _, err := decodeFrameForConfig(padded, 1, c); err != nil {
			t.Fatal("exact raw cap rejected", name, err)
		}
		oversize := bytes.Replace(padded, needle, append(bytes.Clone(needle), ' '), 1)
		if _, err := decodeFrameForConfig(oversize, 1, c); err == nil {
			t.Fatal("raw cap overflow accepted", name)
		}
	}
	f.WindowsInventory.CollectedAt = f.Observation.Observation.LastSeen.Add(time.Nanosecond)
	bad, _ := json.Marshal(f)
	if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
		t.Fatal("snapshot newer than device accepted")
	}
}

func TestWindowsInventoryNoCollectionOutsideExactConsent(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.CollectionProfile = enrollmentcrypto.CollectionProfile }, func(c *Config) { c.SchemaVersion = GuidedConfigVersion }, func(c *Config) { c.Profile = "http-test" }} {
		c := windowsConfig(Config{})
		mutate(&c)
		called := false
		_, _, err := collectWindowsFrame(context.Background(), c, 1, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
			called = true
			return windowsmanaged.Snapshot{}, model.Device{}, nil
		})
		if !errors.Is(err, ErrConfiguration) || called {
			t.Fatal("wrong consent invoked collection")
		}
	}
	for _, seq := range []uint64{0, operational.MaxSafeInteger + 1} {
		_, _, err := collectWindowsFrame(context.Background(), windowsConfig(Config{}), seq, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
			t.Fatal("invalid sequence collected")
			return windowsmanaged.Snapshot{}, model.Device{}, nil
		})
		if !errors.Is(err, ErrState) {
			t.Fatal("sequence domain bypassed")
		}
	}
	for _, scenario := range []string{"error", "wrong-generation", "wrong-platform", "future-time", "oversized-basic"} {
		_, _, err := collectWindowsFrame(context.Background(), windowsConfig(Config{}), 1, func(ctx context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
			s, d, err := windowsSource(ctx, generation)
			switch scenario {
			case "error":
				err = errors.New("fixture failure")
			case "wrong-generation":
				s.GenerationID = "sample_" + strings.Repeat("2", 32)
			case "wrong-platform":
				d.Platform = "linux"
			case "future-time":
				s.CollectedAt = d.LastSeen.Add(time.Second)
			case "oversized-basic":
				for range 64 {
					d.Capabilities = append(d.Capabilities, model.Capability{ID: "fixture", Name: "fixture", Status: "limited", Detail: strings.Repeat("x", 4096)})
				}
			}
			return s, d, err
		})
		if !errors.Is(err, ErrObservation) {
			t.Fatal("invalid source accepted", scenario, err)
		}
	}
}
