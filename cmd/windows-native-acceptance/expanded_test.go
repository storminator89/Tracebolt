package main

import (
	"context"
	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
	"testing"
	"time"
)

type expandedFakeDriver struct {
	*fakeDriver
	configured bool
}

func (d *expandedFakeDriver) ConfigureCapabilities(c context.Context, g native.Guard) error {
	if !g.Check() || !d.e.Stopped || !d.e.Ready || d.call("capabilities") != nil {
		return native.ErrAcceptance
	}
	d.configured = true
	return nil
}
func expandedObservation() profile.ExtensionObservation {
	c := profile.QualityCounts{Observed: 1, Denied: 1}
	return profile.ExtensionObservation{Frames: 1, V5Frames: 1, EventApplication: "observed", EventSystem: "partial", Volumes: "observed", VolumeCapacity: "partial", ProcessCPU: "partial", ProcessMemory: "partial", Network: "partial", VolumeRows: 2, ProcessRows: 2, NetworkRows: 1, PeerLoopbackRows: 1, VolumeCapacityCounts: c, ProcessCPUCounts: c, ProcessMemoryCounts: c}
}
func TestExpandedControllerRequiresStoppedGrantAndUsefulV5(t *testing.T) {
	for _, fail := range []string{"", "capabilities"} {
		_, base, f, h := controllerFixture(t)
		sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		g, err := gate.Authorize(gate.Approval{ExpectedSource: sha, Services: true, Identity: true, AppACLs: true, Loopback: true, Cleanup: true, Selection: profile.InventoryTLS(), InventoryMetadata: true, EventHeaders: true, VisibleVolumes: true, ProcessMetrics: true, NetworkEndpoints: true}, gate.Environment{Event: "workflow_dispatch", Actions: "true", RunnerOS: "Windows", RunnerEnvironment: "github-hosted", Repository: gate.Repository, Source: sha, RunID: "42"}, sha)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		d := &expandedFakeDriver{fakeDriver: base}
		d.fail = fail
		f.b.CollectionProfile = "windows-inventory-v1"
		f.e.Extensions = profile.ZeroExtensionObservation()
		h.newDriver = func(native.Options) (driver, error) { return d, nil }
		h.startExpanded = func(context.Context, profile.Selection) (peer, error) { return f, nil }
		oldPause := h.pause
		h.pause = func(c context.Context, wait time.Duration) error {
			err := oldPause(c, wait)
			if d.configured && !f.e.Unavailable {
				f.e.Extensions = expandedObservation()
			}
			return err
		}
		r := executeWith(context.Background(), g, native.Options{Expanded: true}, h)
		if gate.Validate(r) != nil || r.Schema != gate.ExpandedSchema || r.Extensions == nil || r.ProductionManagerExercised {
			t.Fatal("invalid expanded evidence")
		}
		if fail == "" && (r.Status != "passed_native_subset" || !r.Extensions.Usable()) {
			t.Fatal("full scope failed")
		}
		if fail != "" && (r.Status != "failed" || !r.Native.Cleaned || !r.Native.Uninstalled || r.Extensions.Frames != 0) {
			t.Fatal("configuration failure misreported")
		}
	}
}
func TestExpandedControllerCannotFallbackToBasePeer(t *testing.T) {
	g, _, _, h := controllerFixture(t)
	r := executeWith(context.Background(), g, native.Options{Expanded: true}, h)
	if r.NativeActionsAttempted || r.Status == "passed_native_subset" {
		t.Fatal("mismatched expanded options accepted")
	}
}
