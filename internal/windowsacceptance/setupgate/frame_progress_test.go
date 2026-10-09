package setupgate

import (
	"bytes"
	"encoding/json"
	"testing"

	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/profile"
)

func progressEvidence() fixture.Evidence {
	return fixture.Evidence{
		Frames:     2,
		Inventory:  profile.Observation{Frames: 2, CPU: "healthy", Memory: "healthy", Disk: "healthy", Hostname: "healthy", Processes: "partial", Services: "partial", Software: "partial", Interfaces: "healthy"},
		Extensions: profile.ExtensionObservation{Frames: 2, V5Frames: 2, EventApplication: "bounded", EventSystem: "observed", Volumes: "observed", VolumeCapacity: "observed", ProcessCPU: "observed", ProcessMemory: "observed", Network: "partial", VolumeRows: 1, ProcessRows: 1, NetworkRows: 1, PeerLoopbackRows: 1, VolumeCapacityCounts: profile.QualityCounts{Observed: 1}, ProcessCPUCounts: profile.QualityCounts{Observed: 1}, ProcessMemoryCounts: profile.QualityCounts{Observed: 1}},
		Telemetry:  fixture.TelemetryObservation{Admitted: 2, Accepted: 2},
	}
}

func TestFrameProgressPreservesIncompleteObservations(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*fixture.Evidence)
	}{
		{"no-frame", "no_accepted_frames", func(e *fixture.Evidence) {
			*e = fixture.Evidence{Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation()}
		}},
		{"receiver-rejected", "no_accepted_frames", func(e *fixture.Evidence) {
			*e = fixture.Evidence{Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation(), Telemetry: fixture.TelemetryObservation{Admitted: 1, FrameRejected: 1}}
		}},
		{"receiver-in-flight", "no_accepted_frames", func(e *fixture.Evidence) {
			*e = fixture.Evidence{Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation(), Telemetry: fixture.TelemetryObservation{Admitted: 2, InFlight: 2}}
		}},
		{"inventory-denied", "inventory_unusable", func(e *fixture.Evidence) { e.Inventory.Services = "denied" }},
		{"events-denied", "extensions_unusable", func(e *fixture.Evidence) { e.Extensions.EventApplication = "denied" }},
		{"first-sample", "extensions_unusable", func(e *fixture.Evidence) {
			e.Extensions.ProcessCPU = "first-sample"
			e.Extensions.ProcessCPUCounts = profile.QualityCounts{FirstSample: 1}
			e.Extensions.ProcessCPUFirstSampleRows = 1
		}},
		{"capacity-denied", "extensions_unusable", func(e *fixture.Evidence) {
			e.Extensions.VolumeCapacity = "denied"
			e.Extensions.VolumeCapacityCounts = profile.QualityCounts{Denied: 1}
		}},
		{"memory-denied", "extensions_unusable", func(e *fixture.Evidence) {
			e.Extensions.ProcessMemory = "denied"
			e.Extensions.ProcessMemoryCounts = profile.QualityCounts{Denied: 1}
		}},
		{"peer-omitted", "extensions_unusable", func(e *fixture.Evidence) { e.Extensions.PeerLoopbackRows = 0 }},
		{"base-only", "extensions_unusable", func(e *fixture.Evidence) { e.Extensions = profile.ZeroExtensionObservation() }},
		{"one-v5", "insufficient_v5_frames", func(e *fixture.Evidence) { e.Extensions.Frames = 1; e.Extensions.V5Frames = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := progressEvidence()
			tc.change(&e)
			p, err := ObserveFrames(e)
			if err != nil || p.Validate() != nil || p.Ready() || p.Reason != tc.reason || p.AcceptedFrames != e.Frames || p.Inventory != e.Inventory || p.Extensions != e.Extensions || p.Telemetry != e.Telemetry {
				t.Fatal("incomplete observation lost or promoted")
			}
			if tc.name == "inventory-denied" || tc.name == "events-denied" {
				if p.Telemetry.Accepted != 2 || p.Telemetry.FrameRejected != 0 || p.Telemetry.AuthorizationRejected != 0 {
					t.Fatal("legitimate collection denial was relabeled receiver rejection")
				}
			}
		})
	}
}

func TestFrameProgressReadyRequiresUnchangedPositivePredicate(t *testing.T) {
	e := progressEvidence()
	p, err := ObserveFrames(e)
	if err != nil || !p.Ready() || p.Reason != "complete" {
		t.Fatal("valid bounded partial observations rejected")
	}
	e.Telemetry.Admitted += 3
	e.Telemetry.Duplicate = 2
	e.Telemetry.FrameRejected = 1
	p, err = ObserveFrames(e)
	if err != nil || !p.Ready() || p.Extensions.V5Frames != 2 {
		t.Fatal("receiver history incorrectly changes latest valid proof")
	}
	e.Extensions.V5Frames, e.Extensions.Frames = 1, 1
	p, err = ObserveFrames(e)
	if err != nil || p.Ready() {
		t.Fatal("duplicate receipts supplied a missing distinct v5 frame")
	}
}

func TestFrameProgressRejectsContradictoryAndPrivateEvidence(t *testing.T) {
	p, err := ObserveFrames(progressEvidence())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*FrameProgress){
		func(p *FrameProgress) { p.Reason = "private error or path" },
		func(p *FrameProgress) { p.Reason = "not_started" },
		func(p *FrameProgress) { p.Reason = "inventory_unusable" },
		func(p *FrameProgress) { p.AcceptedFrames = 1 },
		func(p *FrameProgress) { p.Telemetry.Accepted = 1 },
		func(p *FrameProgress) { p.Inventory.Frames = 1 },
		func(p *FrameProgress) { p.Extensions.Frames = 3; p.Extensions.V5Frames = 3 },
		func(p *FrameProgress) { p.Inventory.CPU = "private value" },
		func(p *FrameProgress) { p.Extensions.Network = "private value" },
		func(p *FrameProgress) { p.Extensions.PeerLoopbackRows = 2 },
		func(p *FrameProgress) { p.Telemetry.Admitted = ^uint64(0) },
		func(p *FrameProgress) { p.Telemetry.AuthorizationRejected = ^uint64(0) },
		func(p *FrameProgress) { p.Telemetry.InFlight = 3; p.Telemetry.Admitted += 3 },
	} {
		n := p
		change(&n)
		if n.Validate() == nil || n.Ready() {
			t.Fatal("malformed progress accepted")
		}
	}
	zero := ZeroFrameProgress()
	if zero.Validate() != nil || zero.Ready() {
		t.Fatal("canonical unstarted state invalid")
	}
	zero.Telemetry.Admitted, zero.Telemetry.FrameRejected = 1, 1
	if zero.Validate() == nil {
		t.Fatal("not_started hid a request")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("collectedAt"), []byte("grantId"), []byte("generationId"), []byte("serviceSID"), []byte("processID"), []byte("127.0.0.1"), []byte("raw"), []byte("path")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatal("progress contains private fields")
		}
	}
	// Malformed fixture evidence fails closed without returning partial/private data.
	e := progressEvidence()
	e.Inventory.CPU = "PRIVATE"
	n, err := ObserveFrames(e)
	if err != ErrGuard || n != ZeroFrameProgress() {
		t.Fatal("invalid snapshot escaped")
	}
	e = progressEvidence()
	e.Platform, e.CollectionProfile, e.Transport = "PRIVATE_HOST", "PRIVATE_IDENTITY", "PRIVATE_DESTINATION"
	n, err = ObserveFrames(e)
	if err != nil || n != p {
		t.Fatal("projection retained unrelated fixture metadata")
	}
}
