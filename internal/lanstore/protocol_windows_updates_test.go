package lanstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/bundle"
	"localrmm/internal/model"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"strings"
	"testing"
	"time"
)

func updateProtocolSection[T any](rows []T) windowsinventory.Section[T] {
	return windowsinventory.Section[T]{Source: "Injected fixture", Scope: "Synthetic caller-visible scope", Quality: "healthy", Complete: true, Rows: rows}
}

// Pure invented reports only: these fixtures never invoke a native collector.
func updateProtocolFrame(t *testing.T, at time.Time, siblings int) Frame {
	t.Helper()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Injected unavailable metric", CollectedAt: at}
	report := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Invented Windows", Uptime: "unknown", CPU: metric, Memory: metric, Disk: metric,
		Hostname: updateProtocolSection([]windowsinventory.Hostname{{Value: "invented"}}), Processes: updateProtocolSection([]windowsinventory.Process{}), Services: updateProtocolSection([]windowsinventory.Service{}), Software: updateProtocolSection([]windowsinventory.Software{}), Network: updateProtocolSection([]windowsinventory.InterfaceAddress{})}
	inventory, device, err := windowsmanaged.FromReport(report, "sample_"+strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{SchemaVersion: FrameWindowsUpdatesVersion, Sequence: 1, Observation: bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", Platform: "windows", Architecture: "amd64", GeneratedAt: at.Add(time.Second), Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}, WindowsInventory: &inventory}
	frame.WindowsUpdates = &windowsupdates.Snapshot{SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope, GrantID: strings.Repeat("9", 32), GenerationID: inventory.GenerationID, CollectedAt: at, Source: "wua-cache", CacheFreshness: "unknown", Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsupdates.Update{{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 1, Title: "Invented cached update", KBArticleIDs: []string{"KB123456"}, Severity: "important"}}}
	if siblings&1 != 0 {
		frame.WindowsEvents = &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("a", 32), GenerationID: inventory.GenerationID, CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	}
	if siblings&2 != 0 {
		frame.WindowsVolumes = &windowsvolumes.Snapshot{SchemaVersion: windowsvolumes.SchemaVersion, Scope: windowsvolumes.Scope, GrantID: strings.Repeat("b", 32), GenerationID: inventory.GenerationID, CollectedAt: at, Quality: "observed", Complete: true, CountExact: true, Rows: []windowsvolumes.Volume{}}
	}
	if siblings&4 != 0 {
		frame.WindowsProcessMetrics = &windowsprocessmetrics.Snapshot{SchemaVersion: windowsprocessmetrics.SchemaVersion, Scope: windowsprocessmetrics.Scope, GrantID: strings.Repeat("c", 32), GenerationID: inventory.GenerationID, CollectedAt: at, Rows: []windowsprocessmetrics.Process{}}
	}
	if siblings&8 != 0 {
		frame.WindowsNetwork = &windowsnetwork.Snapshot{SchemaVersion: windowsnetwork.SchemaVersion, Scope: windowsnetwork.Scope, GrantID: strings.Repeat("d", 32), GenerationID: inventory.GenerationID, CollectedAt: at, Quality: "observed", CountExact: true, Rows: []windowsnetwork.Endpoint{}}
	}
	if siblings&16 != 0 {
		digest, err := windowsmanaged.ServiceStartupRowsSHA256(inventory.Services.Rows)
		if err != nil {
			t.Fatal(err)
		}
		frame.WindowsServiceStartup = &windowsmanaged.ServiceStartupSnapshot{SchemaVersion: windowsmanaged.ServiceStartupSchemaVersion, Scope: windowsmanaged.ServiceStartupScope, GrantID: strings.Repeat("e", 32), GenerationID: inventory.GenerationID, CollectedAt: at, ServicesSHA256: digest, Rows: []windowsmanaged.ServiceStartupRow{}}
	}
	return frame
}

func TestWindowsUpdatesV7AllSiblingShapesAndOldBytes(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for bits := 0; bits < 32; bits++ {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			frame := updateProtocolFrame(t, at, bits)
			raw, _ := json.Marshal(frame)
			parsed, err := ValidateFrame(raw, at.Add(time.Second))
			if err != nil || !FrameMatchesCollectionProfile(parsed, windowsmanaged.CollectionProfile) {
				t.Fatal("v7 scope combination rejected", err)
			}
			for _, profile := range []string{"basic-readonly-v1", "managed-operations-v1", "managed-packages-v1", "complete-readonly-v1"} {
				if FrameMatchesCollectionProfile(parsed, profile) {
					t.Fatal("updates crossed collection profile", profile)
				}
			}
			frame.WindowsUpdates = nil
			frame.SchemaVersion = FrameWindowsInventoryVersion
			if bits&1 != 0 {
				frame.SchemaVersion = FrameWindowsEventsVersion
			}
			if bits&2 != 0 {
				frame.SchemaVersion = FrameWindowsCapabilitiesVersion
			}
			if bits&4 != 0 {
				frame.SchemaVersion = FrameWindowsProcessMetricsVersion
			}
			if bits&8 != 0 {
				frame.SchemaVersion = FrameWindowsNetworkVersion
			}
			if bits&16 != 0 {
				frame.SchemaVersion = FrameWindowsServiceStartupVersion
			}
			old, _ := json.Marshal(frame)
			parsed, err = ValidateFrame(old, at.Add(time.Second))
			if err != nil || !FrameMatchesCollectionProfile(parsed, windowsmanaged.CollectionProfile) {
				t.Fatal("old scope frame changed", err)
			}
			roundtrip, _ := json.Marshal(parsed)
			if !bytes.Equal(old, roundtrip) || bytes.Contains(old, []byte("windowsUpdates")) {
				t.Fatal("absent scope changed old bytes")
			}
			frame.WindowsUpdates = updateProtocolFrame(t, at, 0).WindowsUpdates
			bad, _ := json.Marshal(frame)
			if _, err = ValidateFrame(bad, at.Add(time.Second)); err == nil {
				t.Fatal("updates admitted under old version")
			}
		})
	}
}

func TestWindowsUpdatesV7RejectsMalformedBindingsAndClosedShapes(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	changes := map[string]func(*Frame){
		"nil-updates":      func(f *Frame) { f.WindowsUpdates = nil },
		"nil-base":         func(f *Frame) { f.WindowsInventory = nil },
		"cross-generation": func(f *Frame) { f.WindowsUpdates.GenerationID = "sample_" + strings.Repeat("2", 32) },
		"invalid-grant":    func(f *Frame) { f.WindowsUpdates.GrantID = "" },
		"event-grant":      func(f *Frame) { f.WindowsUpdates.GrantID = f.WindowsEvents.GrantID },
		"volume-grant":     func(f *Frame) { f.WindowsUpdates.GrantID = f.WindowsVolumes.GrantID },
		"process-grant":    func(f *Frame) { f.WindowsUpdates.GrantID = f.WindowsProcessMetrics.GrantID },
		"network-grant":    func(f *Frame) { f.WindowsUpdates.GrantID = f.WindowsNetwork.GrantID },
		"startup-grant":    func(f *Frame) { f.WindowsUpdates.GrantID = f.WindowsServiceStartup.GrantID },
		"before-base":      func(f *Frame) { f.WindowsUpdates.CollectedAt = at.Add(-time.Nanosecond) },
		"after-base":       func(f *Frame) { f.WindowsUpdates.CollectedAt = at.Add(time.Nanosecond) },
		"scope":            func(f *Frame) { f.WindowsUpdates.Scope = windowsmanaged.CollectionProfile },
		"source":           func(f *Frame) { f.WindowsUpdates.Source = "online" },
		"freshness":        func(f *Frame) { f.WindowsUpdates.CacheFreshness = "current" },
		"count":            func(f *Frame) { f.WindowsUpdates.ObservedCount = 0 },
		"count-exact":      func(f *Frame) { f.WindowsUpdates.CountExact = false },
		"truncation":       func(f *Frame) { f.WindowsUpdates.Truncated = true },
		"quality":          func(f *Frame) { f.WindowsUpdates.Quality = "healthy" },
		"raw-error":        func(f *Frame) { f.WindowsUpdates.Reason = "private error path" },
		"duplicate-row": func(f *Frame) {
			f.WindowsUpdates.Rows = append(f.WindowsUpdates.Rows, f.WindowsUpdates.Rows[0])
			f.WindowsUpdates.ObservedCount++
		},
		"title":    func(f *Frame) { f.WindowsUpdates.Rows[0].Title = "bad\nvalue" },
		"KB":       func(f *Frame) { f.WindowsUpdates.Rows[0].KBArticleIDs = []string{"https://bad.invalid"} },
		"severity": func(f *Frame) { f.WindowsUpdates.Rows[0].Severity = "safe" },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			f := updateProtocolFrame(t, at, 31)
			mutate(&f)
			raw, _ := json.Marshal(f)
			if _, err := ValidateFrame(raw, at.Add(time.Second)); err == nil {
				t.Fatal("malformed update admitted")
			}
		})
	}
	raw, _ := json.Marshal(updateProtocolFrame(t, at, 0))
	for name, bad := range map[string][]byte{
		"unknown-envelope":   bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"admin":true`), 1),
		"unknown-snapshot":   bytes.Replace(raw, []byte(`"source":"wua-cache"`), []byte(`"source":"wua-cache","description":"private"`), 1),
		"duplicate-snapshot": bytes.Replace(raw, []byte(`"source":"wua-cache"`), []byte(`"source":"wua-cache","source":"wua-cache"`), 1),
		"explicit-null":      bytes.Replace(raw, []byte(`"windowsUpdates":{`), []byte(`"windowsEvents":null,"windowsUpdates":{`), 1),
		"null-required":      bytes.Replace(raw, []byte(`"countExact":true`), []byte(`"countExact":null`), 1),
		"whole-frame-limit":  append(raw, bytes.Repeat([]byte(" "), MaxFrameBytes-len(raw)+1)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateFrame(bad, at.Add(time.Second)); err == nil {
				t.Fatal("open frame accepted")
			}
		})
	}
	if _, err := ValidateFrame(raw, at.Add(SampleMaxAge+time.Second)); !errors.Is(err, ErrStale) {
		t.Fatal("stale updates admitted", err)
	}
	if _, err := ValidateFrame(raw, at.Add(-AllowedClockSkew-time.Second)); !errors.Is(err, ErrStale) {
		t.Fatal("future updates admitted", err)
	}
}

func TestWindowsUpdatesSnapshotAndAggregateBudgets(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	frame := updateProtocolFrame(t, at, 0)
	// Every individual retained snapshot can fit while their complete envelope
	// does not. A sender must trim the complete frame, not add per-scope budgets.
	for n := 0; n < windowsmanaged.MaxSoftwareRows; n++ {
		row := windowsmanaged.Software{Name: fmt.Sprintf("%03d", n) + strings.Repeat("N", 253), Version: strings.Repeat("v", 256), Publisher: strings.Repeat("p", 256), RegistryView: "64"}
		frame.WindowsInventory.Software.Rows = append(frame.WindowsInventory.Software.Rows, row)
		frame.WindowsInventory.Software.ObservedCount++
		if windowsmanaged.Validate(*frame.WindowsInventory) != nil {
			frame.WindowsInventory.Software.Rows = frame.WindowsInventory.Software.Rows[:n]
			frame.WindowsInventory.Software.ObservedCount--
			break
		}
	}
	frame.WindowsUpdates.Rows = []windowsupdates.Update{}
	frame.WindowsUpdates.ObservedCount = 0
	for n := 0; n < windowsupdates.MaxRows; n++ {
		row := windowsupdates.Update{UpdateID: fmt.Sprintf("%08x-2222-3333-4444-555555555555", n+1), Revision: 1, Title: strings.Repeat("U", 256), KBArticleIDs: []string{"KB1234567890", "KB1234567891", "KB1234567892", "KB1234567893", "KB1234567894", "KB1234567895", "KB1234567896", "KB1234567897"}, Severity: "important"}
		frame.WindowsUpdates.Rows = append(frame.WindowsUpdates.Rows, row)
		frame.WindowsUpdates.ObservedCount++
		if windowsupdates.Validate(*frame.WindowsUpdates) != nil {
			frame.WindowsUpdates.Rows = frame.WindowsUpdates.Rows[:n]
			frame.WindowsUpdates.ObservedCount--
			break
		}
	}
	if windowsmanaged.Validate(*frame.WindowsInventory) != nil || windowsupdates.Validate(*frame.WindowsUpdates) != nil {
		t.Fatal("individual bound fixture invalid")
	}
	raw, _ := json.Marshal(frame)
	if len(raw) <= MaxFrameBytes {
		t.Fatalf("fixture did not exceed complete envelope: %d", len(raw))
	}
	if _, err := ValidateFrame(raw, at.Add(time.Second)); !errors.Is(err, ErrFrame) {
		t.Fatal("individually bounded snapshots bypassed whole-frame limit", err)
	}
	// A 65-row snapshot remains under the complete frame cap, but must fail its
	// own limit even if its metadata and observed count are otherwise coherent.
	frame = updateProtocolFrame(t, at, 0)
	for n := 1; n <= windowsupdates.MaxRows; n++ {
		row := frame.WindowsUpdates.Rows[0]
		row.UpdateID = fmt.Sprintf("%08x-2222-3333-4444-555555555555", 0x11111111+n)
		frame.WindowsUpdates.Rows = append(frame.WindowsUpdates.Rows, row)
		frame.WindowsUpdates.ObservedCount++
	}
	raw, _ = json.Marshal(frame)
	if len(raw) > MaxFrameBytes {
		t.Fatal("row limit fixture accidentally tests whole frame")
	}
	if _, err := ValidateFrame(raw, at.Add(time.Second)); !errors.Is(err, ErrFrame) {
		t.Fatal("65 update rows admitted", err)
	}
}

func TestWindowsUpdatesCacheQualityNeverBecomesPatchAssessment(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, quality := range []string{"observed", "partial", "denied", "unavailable"} {
		t.Run(quality, func(t *testing.T) {
			frame := updateProtocolFrame(t, at, 0)
			updates := frame.WindowsUpdates
			updates.Rows = []windowsupdates.Update{}
			updates.ObservedCount = 0
			updates.Quality = quality
			updates.CountExact = quality == "observed"
			switch quality {
			case "partial":
				updates.Reason = windowsupdates.ErrPartial.Error()
			case "denied":
				updates.Reason = windowsupdates.ErrDenied.Error()
			case "unavailable":
				updates.Reason = windowsupdates.ErrUnavailable.Error()
			}
			raw, _ := json.Marshal(frame)
			parsed, err := ValidateFrame(raw, at.Add(time.Second))
			if err != nil || parsed.WindowsUpdates.Quality != quality || parsed.WindowsUpdates.CacheFreshness != "unknown" || parsed.WindowsUpdates.CountExact != updates.CountExact {
				t.Fatal("empty cache quality/freshness lost", err)
			}
			basic, _ := json.Marshal(parsed.Observation)
			if bytes.Contains(basic, []byte("wua-cache")) || bytes.Contains(basic, []byte("Invented cached update")) || bytes.Contains(basic, []byte("KB123456")) {
				t.Fatal("update scope became public health evidence")
			}
		})
	}
}
