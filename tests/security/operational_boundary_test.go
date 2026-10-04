package security_test

import (
	"encoding/json"
	"localrmm/internal/operational"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// These public-contract tests use synthetic values only. They do not call
// Collect, enumerate host processes/packages/journals, execute commands, open
// sender state, or perform network I/O.
func operationalBoundaryPointer[T any](v T) *T { return &v }

func operationalBoundaryFixture() operational.Snapshot {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	s := operational.Empty(now, operational.ReasonSourceMissing)
	meta := func(limit int) operational.SectionMeta {
		return operational.SectionMeta{GenerationID: s.GenerationID, Quality: operational.Healthy, Reason: operational.ReasonNone, ObservedAt: now, Complete: true, ObservedCount: 1, CountExact: true, ItemLimit: limit}
	}
	s.Sections.Volumes = operational.VolumeSection{Meta: meta(operational.VolumeLimit), Items: []operational.Volume{{ID: "mount_12", MountPoint: "/srv/synthetic", Filesystem: "ext4", Kind: "local", TotalBytes: operationalBoundaryPointer(uint64(100)), AvailableBytes: operationalBoundaryPointer(uint64(25)), UsedPercent: operationalBoundaryPointer(float64(75)), MeasurementQuality: operational.Healthy, MeasurementReason: operational.ReasonNone}}}
	s.Sections.Network = operational.NetworkSection{Meta: meta(operational.NetworkLimit), Items: []operational.NetworkInterface{{Name: "fixture0", State: "up", MTU: operationalBoundaryPointer(uint64(1500)), RXBytes: operationalBoundaryPointer(uint64(10)), TXBytes: operationalBoundaryPointer(uint64(20)), RXErrors: operationalBoundaryPointer(uint64(0)), TXErrors: operationalBoundaryPointer(uint64(0)), IPv4Count: operationalBoundaryPointer(uint64(1)), IPv6Count: operationalBoundaryPointer(uint64(0))}}}
	s.Sections.Services = operational.ServiceSection{Meta: meta(operational.ServiceLimit), Items: []operational.Service{{Name: "fixture.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}}}
	s.Sections.Processes = operational.ProcessSection{Meta: meta(operational.ProcessLimit), Items: []operational.Process{{PID: 42, ParentPID: operationalBoundaryPointer(uint64(1)), Name: "fixture-worker", State: "sleeping", RSSBytes: operationalBoundaryPointer(uint64(4096)), CPUTimeSeconds: operationalBoundaryPointer(float64(0.2)), Threads: operationalBoundaryPointer(uint64(1))}}}
	s.Sections.Software = operational.SoftwareSection{Meta: meta(operational.SoftwareLimit), Items: []operational.Software{{Name: "fixture-package", Version: "1.0-1", Architecture: "amd64", Manager: "dpkg"}}}
	s.Sections.Events = operational.EventSection{Meta: meta(operational.EventLimit), Items: []operational.Event{{Source: "systemd-journal", Unit: "fixture.service", Priority: 3, MessageID: "0123456789abcdef0123456789abcdef", Count: 2, FirstSeen: now.Add(-time.Minute), LastSeen: now}}}
	s.Sections.Events.Meta.ObservedCount = 2
	return s
}

func TestIndependentOperationalGenerationCoverageAndMountBoundary(t *testing.T) {
	if err := operational.Validate(operationalBoundaryFixture()); err != nil {
		t.Fatal("synthetic baseline invalid", err)
	}
	cases := map[string]func(*operational.Snapshot){
		"wrong profile": func(s *operational.Snapshot) { s.CollectionProfile = "basic-readonly-v1" },
		"old section generation": func(s *operational.Snapshot) {
			s.Sections.Services.Meta.GenerationID = "sample_00000000000000000000000000000000"
		},
		"old section observation":       func(s *operational.Snapshot) { s.Sections.Services.Meta.ObservedAt = s.CollectedAt.Add(-time.Minute) },
		"empty healthy denied":          func(s *operational.Snapshot) { s.Sections.Services.Meta.Quality = operational.Denied },
		"false complete sample":         func(s *operational.Snapshot) { s.Sections.Services.Meta.ObservedCount = 10 },
		"false complete event total":    func(s *operational.Snapshot) { s.Sections.Events.Meta.ObservedCount = 10 },
		"truncated complete":            func(s *operational.Snapshot) { s.Sections.Services.Meta.Truncated = true },
		"inexact complete":              func(s *operational.Snapshot) { s.Sections.Services.Meta.CountExact = false },
		"limit expanded":                func(s *operational.Snapshot) { s.Sections.Services.Meta.ItemLimit++ },
		"missing items":                 func(s *operational.Snapshot) { s.Sections.Services.Items = nil },
		"forged local mount":            func(s *operational.Snapshot) { s.Sections.Volumes.Items[0].Filesystem = "nfs" },
		"mount ID exceeds kernel range": func(s *operational.Snapshot) { s.Sections.Volumes.Items[0].ID = "mount_9999999999" },
		"home account label":            func(s *operational.Snapshot) { s.Sections.Volumes.Items[0].MountPoint = "/home/synthetic-account/data" },
		"run account ID":                func(s *operational.Snapshot) { s.Sections.Volumes.Items[0].MountPoint = "/run/user/12345/data" },
		"missing volume evidence":       func(s *operational.Snapshot) { s.Sections.Volumes.Items[0].TotalBytes = nil },
		"unavailable volume numeric zero": func(s *operational.Snapshot) {
			s.Sections.Volumes.Items[0].MeasurementQuality = operational.Unknown
			s.Sections.Volumes.Items[0].MeasurementReason = operational.ReasonTimeout
		},
		"future event": func(s *operational.Snapshot) {
			s.Sections.Events.Items[0].LastSeen = s.CollectedAt.Add(time.Nanosecond)
		},
		"out of window event": func(s *operational.Snapshot) {
			s.Sections.Events.Items[0].FirstSeen = s.CollectedAt.Add(-15*time.Minute - time.Nanosecond)
		},
		"duplicated service": func(s *operational.Snapshot) {
			s.Sections.Services.Items = append(s.Sections.Services.Items, s.Sections.Services.Items[0])
			s.Sections.Services.Meta.ObservedCount++
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := operationalBoundaryFixture()
			change(&s)
			if operational.Validate(s) == nil {
				t.Fatal("invalid synthetic contract accepted")
			}
		})
	}
}

func TestIndependentOperationalNumericAndTextBounds(t *testing.T) {
	cases := map[string]func(*operational.Snapshot){
		"duration negative": func(s *operational.Snapshot) { s.DurationMS = -1 },
		"duration unsafe":   func(s *operational.Snapshot) { s.DurationMS = int64(operational.MaxSafeInteger) + 1 },
		"network unsafe integer": func(s *operational.Snapshot) {
			s.Sections.Network.Items[0].RXBytes = operationalBoundaryPointer(operational.MaxSafeInteger + 1)
		},
		"process infinity": func(s *operational.Snapshot) {
			s.Sections.Processes.Items[0].CPUTimeSeconds = operationalBoundaryPointer(math.Inf(1))
		},
		"process NaN": func(s *operational.Snapshot) {
			s.Sections.Processes.Items[0].CPUTimeSeconds = operationalBoundaryPointer(math.NaN())
		},
		"percent over 100": func(s *operational.Snapshot) {
			s.Sections.Volumes.Items[0].UsedPercent = operationalBoundaryPointer(float64(101))
		},
		"invalid UTF8":       func(s *operational.Snapshot) { s.Sections.Processes.Items[0].Name = string([]byte{0xff}) },
		"control newline":    func(s *operational.Snapshot) { s.Sections.Processes.Items[0].Name = "fixture\nsecret" },
		"format control":     func(s *operational.Snapshot) { s.Sections.Processes.Items[0].Name = "fixture\u202e" },
		"multibyte byte cap": func(s *operational.Snapshot) { s.Sections.Processes.Items[0].Name = strings.Repeat("é", 33) },
		"process pathname":   func(s *operational.Snapshot) { s.Sections.Processes.Items[0].Name = "/private/fixture" },
		"package byte cap":   func(s *operational.Snapshot) { s.Sections.Software.Items[0].Version = strings.Repeat("1", 193) },
		"event priority":     func(s *operational.Snapshot) { s.Sections.Events.Items[0].Priority = 8 },
		"raw message ID":     func(s *operational.Snapshot) { s.Sections.Events.Items[0].MessageID = "synthetic raw message body" },
		"byte ceiling": func(s *operational.Snapshot) {
			s.Sections.Software.Items = nil
			for i := 0; i < operational.SoftwareLimit; i++ {
				// A stable two-letter suffix gives each synthetic identity a
				// unique name while exceeding the serialized snapshot ceiling.
				name := strings.Repeat("p", 126) + string(rune('a'+i/26)) + string(rune('a'+i%26))
				s.Sections.Software.Items = append(s.Sections.Software.Items, operational.Software{Name: name, Version: strings.Repeat("1", 192), Architecture: "amd64", Manager: "dpkg"})
			}
			s.Sections.Software.Meta.ObservedCount = operational.SoftwareLimit
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := operationalBoundaryFixture()
			change(&s)
			if operational.Validate(s) == nil {
				t.Fatal("unsafe synthetic value accepted")
			}
		})
	}
}

func TestIndependentOperationalGroupedAndPartialCountsRemainTruthful(t *testing.T) {
	for _, reason := range []operational.Reason{operational.ReasonItemLimit, operational.ReasonByteLimit} {
		s := operationalBoundaryFixture()
		// Enumeration can be exact even when only some discovered records fit.
		s.Sections.Services.Meta.Complete = false
		s.Sections.Services.Meta.Truncated = true
		s.Sections.Services.Meta.Reason = reason
		s.Sections.Services.Meta.ObservedCount = 10
		s.Sections.Events.Meta.Complete = false
		s.Sections.Events.Meta.Truncated = true
		s.Sections.Events.Meta.Reason = reason
		s.Sections.Events.Meta.ObservedCount = 10
		if err := operational.Validate(s); err != nil {
			t.Fatal("truthful truncated/grouped synthetic sample rejected", err)
		}
	}
	s := operationalBoundaryFixture()
	// The event provider counts input records, not aggregate output rows.
	s.Sections.Events.Items[0].Count = 2
	s.Sections.Events.Meta.ObservedCount = 2
	if err := operational.Validate(s); err != nil {
		t.Fatal("complete aggregated event count rejected", err)
	}
	// A successful exact enumeration may truly discover no services.
	s.Sections.Services.Items = []operational.Service{}
	s.Sections.Services.Meta.ObservedCount = 0
	if err := operational.Validate(s); err != nil {
		t.Fatal("genuine complete empty enumeration rejected", err)
	}
}

func TestIndependentOperationalExactExportedFields(t *testing.T) {
	// Freezing the output field set ensures future source-only metadata does not
	// silently become an exported account, address, raw-log or executable field.
	// This is deliberately not an untrusted-JSON decoder test: ingress must reject
	// duplicate, unknown, case-aliased and missing keys before typed validation.
	s := operationalBoundaryFixture()
	checks := []struct {
		name  string
		value any
		keys  string
	}{
		{"snapshot", s, "schemaVersion collectionProfile generationId collectedAt durationMs sections"},
		{"sections", s.Sections, "volumes network services processes software events"},
		{"section", s.Sections.Volumes, "meta items"},
		{"meta", s.Sections.Volumes.Meta, "generationId quality reason observedAt complete truncated observedCount countExact itemLimit"},
		{"volume", s.Sections.Volumes.Items[0], "id mountPoint filesystem kind totalBytes availableBytes usedPercent measurementQuality measurementReason"},
		{"network", s.Sections.Network.Items[0], "name state mtu rxBytes txBytes rxErrors txErrors ipv4Count ipv6Count"},
		{"service", s.Sections.Services.Items[0], "name loadState activeState subState"},
		{"process", s.Sections.Processes.Items[0], "pid parentPid name state rssBytes cpuTimeSeconds threads"},
		{"software", s.Sections.Software.Items[0], "name version architecture manager"},
		{"event", s.Sections.Events.Items[0], "source unit priority messageId count firstSeen lastSeen"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			b, err := json.Marshal(check.value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(fields))
			for name := range fields {
				got = append(got, name)
			}
			want := strings.Fields(check.keys)
			sort.Strings(got)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("operational export field set changed")
			}
		})
	}
}

func TestIndependentOperationalRetainedSectionsPreserveProvenance(t *testing.T) {
	s := operationalBoundaryFixture()
	before, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	checks := []func() error{
		func() error { return operational.ValidateVolumeSection(s.Sections.Volumes) },
		func() error { return operational.ValidateNetworkSection(s.Sections.Network) },
		func() error { return operational.ValidateServiceSection(s.Sections.Services) },
		func() error { return operational.ValidateProcessSection(s.Sections.Processes) },
		func() error { return operational.ValidateSoftwareSection(s.Sections.Software) },
		func() error { return operational.ValidateEventSection(s.Sections.Events) },
	}
	for _, validate := range checks {
		if err := validate(); err != nil {
			t.Fatal("valid original retained section rejected", err)
		}
	}
	after, err := json.Marshal(s)
	if err != nil || string(before) != string(after) {
		t.Fatal("standalone validation rewrote original evidence")
	}
	// Standalone evidence can remain valid without becoming part of a fresh
	// snapshot. Fresh-envelope validation must reject mixed generations/times.
	s.CollectedAt = s.CollectedAt.Add(time.Minute)
	if operational.Validate(s) == nil {
		t.Fatal("old sections gained fresh snapshot provenance")
	}
	if err := operational.ValidateEventSection(s.Sections.Events); err != nil {
		t.Fatal("retained event window did not use original section time", err)
	}
}
