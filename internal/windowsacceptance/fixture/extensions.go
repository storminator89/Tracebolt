package fixture

import (
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsacceptance/profile"
	"net/url"
	"strconv"
	"time"
)

func (s *state) extensionShape(f lanstore.Frame) bool {
	n := 0
	for _, present := range []bool{f.WindowsEvents != nil, f.WindowsVolumes != nil, f.WindowsProcessMetrics != nil, f.WindowsNetwork != nil} {
		if present {
			n++
		}
	}
	if !s.expanded {
		return n == 0
	}
	if !s.selection.Inventory() {
		return false
	}
	if n == 0 {
		return s.extensions.Frames == 0 && f.SchemaVersion == lanstore.FrameWindowsInventoryVersion
	}
	return n == 4 && f.SchemaVersion == lanstore.FrameWindowsNetworkVersion
}

// Independent original-capture floors mirror the production enrollment store.
// The inventory must also advance beyond the previous network capture.
func (s *state) extensionAdvance(f lanstore.Frame) bool {
	if f.WindowsInventory != nil && !s.lastNetworkCollected.IsZero() && !f.WindowsInventory.CollectedAt.After(s.lastNetworkCollected) {
		return false
	}
	checks := [][2]time.Time{}
	if f.WindowsEvents != nil {
		checks = append(checks, [2]time.Time{f.WindowsEvents.CollectedAt, s.lastEventsCollected})
	}
	if f.WindowsVolumes != nil {
		checks = append(checks, [2]time.Time{f.WindowsVolumes.CollectedAt, s.lastVolumesCollected})
	}
	if f.WindowsProcessMetrics != nil {
		checks = append(checks, [2]time.Time{f.WindowsProcessMetrics.CollectedAt, s.lastProcessCollected})
	}
	if f.WindowsNetwork != nil {
		checks = append(checks, [2]time.Time{f.WindowsNetwork.CollectedAt, s.lastNetworkCollected})
	}
	for _, c := range checks {
		if !c[1].IsZero() && !c[0].After(c[1]) {
			return false
		}
	}
	return true
}
func addQuality(c *profile.QualityCounts, q string) {
	switch q {
	case "observed":
		c.Observed++
	case "denied":
		c.Denied++
	case "unavailable":
		c.Unavailable++
	case "first-sample":
		c.FirstSample++
	case "reset":
		c.Reset++
	}
}
func (s *state) observeExtensions(f lanstore.Frame) {
	if !s.expanded || f.WindowsNetwork == nil {
		return
	}
	e, v, p, n := f.WindowsEvents, f.WindowsVolumes, f.WindowsProcessMetrics, f.WindowsNetwork
	o := profile.ExtensionObservation{Frames: s.extensions.Frames + 1, V5Frames: s.extensions.V5Frames + 1, EventApplication: e.Channels[0].Quality, EventSystem: e.Channels[1].Quality, Volumes: v.Quality, VolumeCapacity: "empty", ProcessCPU: "empty", ProcessMemory: "empty", Network: n.Quality, EventRows: uint32(len(e.Channels[0].Rows) + len(e.Channels[1].Rows)), VolumeRows: uint32(len(v.Rows)), ProcessRows: uint32(len(p.Rows)), NetworkRows: uint32(len(n.Rows))}
	for _, row := range v.Rows {
		addQuality(&o.VolumeCapacityCounts, row.Quality)
	}
	for _, row := range p.Rows {
		addQuality(&o.ProcessCPUCounts, row.CPUQuality)
		addQuality(&o.ProcessMemoryCounts, row.MemoryQuality)
		if row.CPUQuality == "first-sample" {
			o.ProcessCPUFirstSampleRows++
		}
	}
	// Match only this peer's numeric IPv4 loopback endpoint. Do not retain the
	// origin/port, inspect process identity, or broaden the collector's bounds.
	origin, err := url.Parse(s.bootstrap.AgentOrigin)
	if err == nil && validOrigin(s.bootstrap.AgentOrigin, s.selection) && origin.Hostname() == "127.0.0.1" {
		port, err := strconv.ParseUint(origin.Port(), 10, 16)
		if err == nil && port > 0 {
			for _, row := range n.Rows {
				if row.Protocol != "tcp" || row.Family != "ipv4" {
					continue
				}
				local := row.LocalAddress == "127.0.0.1" && row.LocalPort == uint16(port)
				remote := row.RemoteAddress != nil && row.RemotePort != nil && *row.RemoteAddress == "127.0.0.1" && *row.RemotePort == uint16(port)
				if local || remote {
					o.PeerLoopbackRows++
				}
			}
		}
	}
	o.VolumeCapacity, o.ProcessCPU, o.ProcessMemory = o.VolumeCapacityCounts.Quality(), o.ProcessCPUCounts.Quality(), o.ProcessMemoryCounts.Quality()
	s.extensions = o
	s.lastEventsCollected, s.lastVolumesCollected, s.lastProcessCollected, s.lastNetworkCollected = e.CollectedAt, v.CollectedAt, p.CollectedAt, n.CollectedAt
}
