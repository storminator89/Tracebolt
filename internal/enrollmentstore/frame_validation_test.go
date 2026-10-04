package enrollmentstore

import (
	"encoding/json"
	"errors"
	"localrmm/internal/lanstore"
	"localrmm/internal/operational"
	"testing"
	"time"
)

func TestTransactionFrameReusePreservesReceiptAndDetachedViews(t *testing.T) {
	at := time.Unix(testNow+10, 123456789).UTC()
	raw, _ := operationalFrame(t, 1, at, true)
	tx := &transaction{}
	first, e := tx.validateFrame(raw, at)
	if e != nil {
		t.Fatal(e)
	}
	first.Operational.Sections.Services.Items[0].Name = "changed.service"
	first.Observation.Observation.Tags[0] = "changed"
	ageSnapshot(first.Operational)
	second, e := tx.validateFrame(raw, at)
	if e != nil || second.Operational.Sections.Services.Items[0].Name != "fixture.service" || second.Operational.Sections.Services.Meta.Quality != operational.Healthy || second.Observation.Observation.Tags[0] != "read-only" {
		t.Fatal("returned view changed pure cached parse")
	}
	second.Operational.Sections.Services.Items[0].Name = "changed-again.service"
	third, e := tx.validateFrame(raw, at)
	if e != nil || third.Operational.Sections.Services.Items[0].Name != "fixture.service" || len(tx.validatedFrames) != 1 {
		t.Fatal("cached return shared mutable state")
	}
	if _, e = tx.validateFrame(raw, at.Add(3*time.Minute)); !errors.Is(e, lanstore.ErrStale) {
		t.Fatal("receipt timestamp omitted from validation key")
	}
	var altered lanstore.Frame
	if json.Unmarshal(raw, &altered) != nil {
		t.Fatal("fixture")
	}
	altered.Operational.Sections.Services.Items[0].Name = "invalid/unit.service"
	changed, _ := json.Marshal(altered)
	if _, e = tx.validateFrame(changed, at); !errors.Is(e, lanstore.ErrFrame) {
		t.Fatal("changed bytes inherited prior validation")
	}
	if len(tx.validatedFrames) != 1 {
		t.Fatal("failed validation was retained")
	}
}

func TestTransactionFrameCloneDetachesEveryPointerCategory(t *testing.T) {
	number := uint64(7)
	percentage := float64(4)
	ip := "fixture"
	var f lanstore.Frame
	f.Observation.Observation.IP = &ip
	f.Observation.Observation.CPU.Value = &percentage
	f.Operational = &operational.Snapshot{Sections: operational.Sections{
		Volumes:   operational.VolumeSection{Items: []operational.Volume{{TotalBytes: &number, AvailableBytes: &number, UsedPercent: &percentage}}},
		Network:   operational.NetworkSection{Items: []operational.NetworkInterface{{MTU: &number, RXBytes: &number, TXBytes: &number, RXErrors: &number, TXErrors: &number, IPv4Count: &number, IPv6Count: &number}}},
		Processes: operational.ProcessSection{Items: []operational.Process{{ParentPID: &number, RSSBytes: &number, Threads: &number, CPUTimeSeconds: &percentage}}},
	}}
	copy := cloneFrame(f)
	*copy.Observation.Observation.IP = "mutated"
	*copy.Observation.Observation.CPU.Value = 99
	volume := &copy.Operational.Sections.Volumes.Items[0]
	for _, p := range []*uint64{volume.TotalBytes, volume.AvailableBytes} {
		*p = 99
	}
	*volume.UsedPercent = 99
	network := &copy.Operational.Sections.Network.Items[0]
	for _, p := range []*uint64{network.MTU, network.RXBytes, network.TXBytes, network.RXErrors, network.TXErrors, network.IPv4Count, network.IPv6Count} {
		*p = 99
	}
	process := &copy.Operational.Sections.Processes.Items[0]
	for _, p := range []*uint64{process.ParentPID, process.RSSBytes, process.Threads} {
		*p = 99
	}
	*process.CPUTimeSeconds = 99
	if number != 7 || percentage != 4 || ip != "fixture" {
		t.Fatal("mutable pointers shared across detached parse")
	}
}
