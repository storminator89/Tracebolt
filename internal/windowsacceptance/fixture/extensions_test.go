package fixture

import (
	"bytes"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"strings"
	"testing"
	"time"
)

// All samples are invented in memory; no native APIs or listeners are invoked.
func expandedFrame(at time.Time, seq uint64, generation string) lanstore.Frame {
	f := inventoryFrame(at, seq, generation)
	f.SchemaVersion = lanstore.FrameWindowsNetworkVersion
	g := strings.Repeat("a", 32)
	f.WindowsInventory.Processes = windowsmanaged.Section[windowsmanaged.Process]{Source: "Invented", Scope: "Invented", Quality: "healthy", ObservedCount: 1, CountExact: true, Complete: true, Rows: []windowsmanaged.Process{{PID: 7, Name: "Invented"}}}
	f.WindowsEvents = &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: g, GenerationID: generation, CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	f.WindowsVolumes = &windowsvolumes.Snapshot{SchemaVersion: windowsvolumes.SchemaVersion, Scope: windowsvolumes.Scope, GrantID: g, GenerationID: generation, CollectedAt: at, Quality: "observed", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsvolumes.Volume{{VolumeID: `\\?\Volume{11111111-1111-1111-1111-111111111111}\`, DriveType: "fixed", Quality: "observed", Capacity: &windowsvolumes.Capacity{TotalBytes: "100", FreeBytes: "80", AvailableBytes: "70"}}}}
	cpu := float64(2)
	ram := "4096"
	f.WindowsProcessMetrics = &windowsprocessmetrics.Snapshot{SchemaVersion: windowsprocessmetrics.SchemaVersion, Scope: windowsprocessmetrics.Scope, GrantID: g, GenerationID: generation, CollectedAt: at, ObservedCount: 1, Rows: []windowsprocessmetrics.Process{{PID: 7, CPUPercent: &cpu, CPUQuality: "observed", MemoryBytes: &ram, MemoryQuality: "observed"}}}
	listen := "listen"
	f.WindowsNetwork = &windowsnetwork.Snapshot{SchemaVersion: windowsnetwork.SchemaVersion, Scope: windowsnetwork.Scope, GrantID: g, GenerationID: generation, CollectedAt: at, Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsnetwork.Endpoint{{Protocol: "tcp", Family: "ipv4", LocalAddress: "127.0.0.1", LocalPort: 18444, State: &listen, PID: 7}}}
	return f
}
func TestExpandedShapeEvidenceAndFallback(t *testing.T) {
	for _, selection := range []profile.Selection{profile.InventoryTLS(), inventorySelection(true)} {
		t.Run(selection.Transport, func(t *testing.T) {
			c := syntheticSelected(t, selection)
			activateSynthetic(c)
			p := selection.TelemetryPath()
			// The old base peer rejects every extension wire version without receipts.
			for _, version := range []string{lanstore.FrameWindowsEventsVersion, lanstore.FrameWindowsCapabilitiesVersion, lanstore.FrameWindowsProcessMetricsVersion, lanstore.FrameWindowsNetworkVersion} {
				f := expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
				f.SchemaVersion = version
				if version != lanstore.FrameWindowsNetworkVersion {
					f.WindowsNetwork = nil
				}
				if version == lanstore.FrameWindowsEventsVersion || version == lanstore.FrameWindowsCapabilitiesVersion {
					f.WindowsProcessMetrics = nil
				}
				if version == lanstore.FrameWindowsEventsVersion {
					f.WindowsVolumes = nil
				}
				if _, e := lanstore.ValidateFrame(encoded(t, f), *c.now); e != nil {
					t.Fatal("invalid invented version", version, e)
				}
				if w := c.post(p, encoded(t, f), true); w.Code != 400 {
					t.Fatal("base accepted extension", version, w.Code)
				}
			}
			c.f.state.expanded = true
			for i := 1; i <= 2; i++ {
				receipt(t, c.post(p, encoded(t, inventoryFrame(*c.now, uint64(i), "sample_"+strings.Repeat(string(rune('0'+i)), 32))), true))
				*c.now = c.now.Add(time.Second)
			}
			f := expandedFrame(*c.now, 3, "sample_"+strings.Repeat("3", 32))
			raw := encoded(t, f)
			receipt(t, c.post(p, raw, true))
			first := c.f.Evidence()
			if first.Extensions.Validate() != nil || !first.Extensions.Usable() || first.Extensions.Frames != 1 || first.Extensions.V5Frames != 1 {
				t.Fatal("missing valid all-four evidence")
			}
			*c.now = c.now.Add(time.Second)
			dup := receipt(t, c.post(p, raw, true))
			if !dup.Duplicate || c.f.Evidence().Extensions != first.Extensions {
				t.Fatal("retry changed evidence")
			}
			if w := c.post(p, encoded(t, inventoryFrame(*c.now, 4, "sample_"+strings.Repeat("4", 32))), true); w.Code != 400 {
				t.Fatal("base fallback admitted")
			}
			out := encoded(t, first.Extensions)
			for _, s := range []string{"127.0.0.1", "18444", "192.0.2", "12345", "4096", "Volume{", "sample_", gToken(), "Invented", "collectedAt", "grantId", "rows"} {
				if bytes.Contains(out, []byte(s)) {
					t.Fatal("evidence leaked content", s)
				}
			}
		})
	}
}
func gToken() string { return strings.Repeat("a", 32) }
func TestExpandedPartialCombinationsRejected(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	c.f.state.expanded = true
	activateSynthetic(c)
	for mask := 1; mask < 15; mask++ {
		f := expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
		if mask&1 == 0 {
			f.WindowsEvents = nil
		}
		if mask&2 == 0 {
			f.WindowsVolumes = nil
		}
		if mask&4 == 0 {
			f.WindowsProcessMetrics = nil
		}
		if mask&8 == 0 {
			f.WindowsNetwork = nil
		}
		if w := c.post(c.f.state.selection.TelemetryPath(), encoded(t, f), true); w.Code != 400 || c.f.Evidence().Frames != 0 {
			t.Fatal("partial expansion admitted", mask)
		}
	}
}
func TestExpandedIndependentCaptureFences(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	c.f.state.expanded = true
	activateSynthetic(c)
	p := c.f.state.selection.TelemetryPath()
	at := *c.now
	f := expandedFrame(at, 1, "sample_"+strings.Repeat("1", 32))
	f.Observation.GeneratedAt = at.Add(2 * time.Second)
	f.WindowsEvents.CollectedAt = at.Add(time.Second)
	f.WindowsVolumes.CollectedAt = at.Add(time.Second)
	f.WindowsProcessMetrics.CollectedAt = at.Add(time.Second)
	f.WindowsNetwork.CollectedAt = at.Add(time.Second)
	*c.now = at.Add(3 * time.Second)
	receipt(t, c.post(p, encoded(t, f), true))
	for _, kind := range []string{"events", "volumes", "process", "network", "inventory-network"} {
		n := expandedFrame(at.Add(time.Second), 2, "sample_"+strings.Repeat("2", 32))
		n.Observation.GeneratedAt = at.Add(3 * time.Second)
		n.WindowsEvents.CollectedAt = at.Add(2 * time.Second)
		n.WindowsVolumes.CollectedAt = at.Add(2 * time.Second)
		n.WindowsProcessMetrics.CollectedAt = at.Add(2 * time.Second)
		n.WindowsNetwork.CollectedAt = at.Add(2 * time.Second)
		if kind != "inventory-network" {
			n.WindowsInventory.CollectedAt = at.Add(2 * time.Second)
			n.Observation.Observation.LastSeen = at.Add(2 * time.Second)
			n.Observation.Observation.CPU.CollectedAt = at.Add(2 * time.Second)
			n.Observation.Observation.Memory.CollectedAt = at.Add(2 * time.Second)
			n.Observation.Observation.Disk.CollectedAt = at.Add(2 * time.Second)
		}
		switch kind {
		case "events":
			n.WindowsEvents.CollectedAt = f.WindowsEvents.CollectedAt
		case "volumes":
			n.WindowsVolumes.CollectedAt = f.WindowsVolumes.CollectedAt
		case "process":
			n.WindowsProcessMetrics.CollectedAt = f.WindowsProcessMetrics.CollectedAt
			n.WindowsInventory.CollectedAt = at.Add(time.Second)
		case "network":
			n.WindowsNetwork.CollectedAt = f.WindowsNetwork.CollectedAt
			n.WindowsInventory.CollectedAt = at.Add(time.Second)
		}
		raw := encoded(t, n)
		if _, e := lanstore.ValidateFrame(raw, *c.now); e != nil {
			t.Fatal("invalid replay fixture", kind, e)
		}
		if w := c.post(p, raw, true); w.Code != 409 || c.f.Evidence().Extensions.Frames != 1 {
			t.Fatal("capture fence failed", kind, w.Code)
		}
	}
}

func TestExpandedQualityCountsAndFirstSample(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	c.f.state.expanded = true
	activateSynthetic(c)
	p := c.f.state.selection.TelemetryPath()
	f := expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
	f.WindowsProcessMetrics.Rows[0].CPUPercent = nil
	f.WindowsProcessMetrics.Rows[0].CPUQuality = "first-sample"
	receipt(t, c.post(p, encoded(t, f), true))
	o := c.f.Evidence().Extensions
	if o.Validate() != nil || o.Usable() || o.ProcessCPU != "first-sample" || o.ProcessCPUFirstSampleRows != 1 {
		t.Fatal("first sample incorrectly proves CPU delta")
	}
	*c.now = c.now.Add(time.Second)
	f = expandedFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32))
	f.WindowsInventory.Processes.Rows = append(f.WindowsInventory.Processes.Rows, windowsmanaged.Process{PID: 8, Name: "Unavailable invented"})
	f.WindowsInventory.Processes.ObservedCount++
	f.WindowsProcessMetrics.ObservedCount++
	f.WindowsProcessMetrics.Rows = append(f.WindowsProcessMetrics.Rows, windowsprocessmetrics.Process{PID: 8, CPUQuality: "denied", MemoryQuality: "unavailable"})
	f.WindowsVolumes.ObservedCount++
	f.WindowsVolumes.Rows = append(f.WindowsVolumes.Rows, windowsvolumes.Volume{VolumeID: `\\?\Volume{22222222-2222-2222-2222-222222222222}\`, DriveType: "fixed", Quality: "denied", Reason: windowsvolumes.ErrDenied.Error()})
	receipt(t, c.post(p, encoded(t, f), true))
	o = c.f.Evidence().Extensions
	if o.Validate() != nil || !o.Usable() || o.ProcessCPU != "partial" || o.ProcessCPUCounts.Denied != 1 || o.ProcessMemoryCounts.Unavailable != 1 || o.VolumeCapacityCounts.Denied != 1 {
		t.Fatal("mixed quality not represented honestly")
	}
	*c.now = c.now.Add(time.Second)
	f = expandedFrame(*c.now, 3, "sample_"+strings.Repeat("3", 32))
	f.WindowsEvents.Channels[0] = windowseventhealth.Channel{Channel: "Application", Quality: "denied", Reason: "windows_events_access_denied", Rows: []windowseventhealth.Event{}}
	receipt(t, c.post(p, encoded(t, f), true))
	o = c.f.Evidence().Extensions
	if o.Validate() != nil || o.Usable() || o.EventApplication != "denied" {
		t.Fatal("denied event channel passed")
	}
}
func TestExpandedExactDuplicateBeforeCaptureAge(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	c.f.state.expanded = true
	activateSynthetic(c)
	p := c.f.state.selection.TelemetryPath()
	raw := encoded(t, expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	first := receipt(t, c.post(p, raw, true))
	*c.now = c.now.Add(lanstore.SampleMaxAge + time.Second)
	if _, err := lanstore.ValidateFrame(raw, *c.now); err == nil {
		t.Fatal("fixture is not stale")
	}
	dup := receipt(t, c.post(p, raw, true))
	if !dup.Duplicate || !dup.ReceivedAt.Equal(first.ReceivedAt) || c.f.Evidence().Extensions.Frames != 1 {
		t.Fatal("exact duplicate lost original acceptance")
	}
}
func TestExpandedMalformedRealDecodersFailClosed(t *testing.T) {
	for _, kind := range []string{"null", "wrong-generation", "nan-cpu", "missing-process", "wrong-grant", "duplicate-field", "foreign-scope"} {
		t.Run(kind, func(t *testing.T) {
			c := syntheticSelected(t, profile.InventoryTLS())
			c.f.state.expanded = true
			activateSynthetic(c)
			f := expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			raw := encoded(t, f)
			switch kind {
			case "null":
				raw = bytes.Replace(raw, []byte(`"windowsNetwork":{`), []byte(`"windowsNetwork":null,"x":{`), 1)
			case "wrong-generation":
				f.WindowsNetwork.GenerationID = "sample_" + strings.Repeat("2", 32)
				raw = encoded(t, f)
			case "nan-cpu":
				raw = bytes.Replace(raw, []byte(`"cpuPercent":2`), []byte(`"cpuPercent":1e999`), 1)
			case "missing-process":
				f.WindowsProcessMetrics.Rows[0].PID = 9
				raw = encoded(t, f)
			case "wrong-grant":
				f.WindowsVolumes.GrantID = "wrong"
				raw = encoded(t, f)
			case "duplicate-field":
				raw = bytes.Replace(raw, []byte(`"windowsNetwork":{`), []byte(`"windowsNetwork":null,"windowsNetwork":{`), 1)
			case "foreign-scope":
				f.WindowsEvents.Scope = "other"
				raw = encoded(t, f)
			}
			if _, err := lanstore.ValidateFrame(raw, *c.now); err == nil {
				t.Fatal("real decoder admitted invalid bytes")
			}
			if w := c.post(c.f.state.selection.TelemetryPath(), raw, true); w.Code != 400 || c.f.Evidence().Frames != 0 {
				t.Fatal("invalid extension committed")
			}
		})
	}
}

func TestExpandedPeerLoopbackProof(t *testing.T) {
	for _, kind := range []string{"listener", "remote-peer", "both-ends", "foreign-port", "udp", "unrelated-loopback", "non-loopback", "empty"} {
		t.Run(kind, func(t *testing.T) {
			c := syntheticSelected(t, profile.InventoryTLS())
			c.f.state.expanded = true
			activateSynthetic(c)
			f := expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			row := &f.WindowsNetwork.Rows[0]
			want := uint32(0)
			switch kind {
			case "listener":
				want = 1
			case "remote-peer", "both-ends":
				state, address, port := "established", "127.0.0.1", uint16(18444)
				row.State = &state
				row.RemoteAddress = &address
				row.RemotePort = &port
				if kind == "remote-peer" {
					row.LocalPort = 32000
				}
				want = 1
			case "foreign-port":
				row.LocalPort = 18443
			case "udp":
				row.Protocol = "udp"
				row.State = nil
			case "unrelated-loopback":
				row.LocalAddress = "127.0.0.2"
			case "non-loopback":
				row.LocalAddress = "192.0.2.20"
			case "empty":
				f.WindowsNetwork.Rows = []windowsnetwork.Endpoint{}
				f.WindowsNetwork.ObservedCount = 0
			}
			raw := encoded(t, f)
			if _, err := lanstore.ValidateFrame(raw, *c.now); err != nil {
				t.Fatal("invalid invented endpoint", err)
			}
			receipt(t, c.post(c.f.state.selection.TelemetryPath(), raw, true))
			o := c.f.Evidence().Extensions
			if o.Validate() != nil || o.PeerLoopbackRows != want || o.Usable() != (want > 0) {
				t.Fatal("peer endpoint proof mismatch", kind, o.PeerLoopbackRows)
			}
		})
	}
}
