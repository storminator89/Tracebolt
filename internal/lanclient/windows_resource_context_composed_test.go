//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssessions"
	"strings"
	"testing"
	"time"
)

func TestWindowsResourceComposedMaximumFitsBeforeBindings(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), 7)
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		for i := 1; i <= 128; i++ {
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: uint32(i), Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Services.Quality, r.Services.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("x", 60), DisplayName: "Fixture", State: "running", PID: 7})
		}
		r.Software.Quality, r.Software.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		return windowsmanaged.FromReport(r, g)
	})
	if err != nil {
		t.Fatal(err)
	}
	original := *f.WindowsInventory
	reserved, e := windowsmanaged.FitPreviewBudgetWithSelfPID(original, windowsResourceContextBaseBytes, 7)
	if e != nil {
		t.Fatal(e)
	}
	f.WindowsInventory = &reserved
	reservedRaw, _ := json.Marshal(reserved)
	if len(reservedRaw) > windowsResourceContextBaseBytes || reserved.Processes.ObservedCount != original.Processes.ObservedCount || reserved.Services.ObservedCount != original.Services.ObservedCount || reserved.Software.ObservedCount != original.Software.ObservedCount || reserved.CollectedAt != original.CollectedAt || reserved.GenerationID != original.GenerationID {
		t.Fatal("reservation changed identity/counts")
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 2100), strings.Repeat("b", 2100), strings.Repeat("c", 2100), "HTTP-test plaintext."}
	f, _, err = appendWindowsEvents(ctx, m, f, eventConsentFixture(m), eventSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), volumeSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), processSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(f.WindowsInventory)
	digest := f.WindowsServiceStartup.ServicesSHA256
	capture := f.WindowsInventory.CollectedAt
	f, _, err = appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), updatesSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsAdapterContext(ctx, m, f, adapterConsentFixture(m), adapterSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsPatchContext(ctx, m, f, patchConsentFixture(m), patchSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsSecurityPosture(ctx, m, f, securityConsentFixture(m), securitySourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsSessionContext(ctx, m, f, sessionConsentFixture(m), func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
		s, e := sessionSourceFixture(ctx, r)
		n := uint32(32)
		zero := uint32(0)
		s.Sessions.ObservedCount = &n
		s.Sessions.RetainedCount = n
		s.Sessions.TruncatedCount = &zero
		s.Sessions.Rows = []windowssessions.Session{}
		for i := uint32(1); i <= 32; i++ {
			name := strings.Repeat("界", 64)
			s.Sessions.Rows = append(s.Sessions.Rows, windowssessions.Session{SessionID: i, UserName: &name, UserQuality: "observed", DomainName: &name, DomainQuality: "observed", State: "active", Protocol: "rdp"})
		}
		join := strings.Repeat("&", 256)
		s.Join = windowssessions.Join{Quality: "observed", Status: "domain", Name: &join}
		if windowssessions.Validate(s) != nil {
			t.Fatal("session source invalid")
		}
		return s, e
	})
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err = appendWindowsHardwareContext(ctx, m, f, hardwareConsentFixture(m), func(ctx context.Context, r windowshardware.Request) (windowshardware.Snapshot, error) {
		s, e := hardwareSourceFixture(ctx, r)
		label := strings.Repeat("&", 128)
		serial := strings.Repeat("&", 64)
		hf := windowshardware.Field{Value: &label, Quality: "observed"}
		sf := windowshardware.Field{Value: &serial, Quality: "observed"}
		s.System = windowshardware.System{Quality: "observed", Manufacturer: hf, Model: hf}
		s.Firmware = windowshardware.Firmware{Quality: "observed", Source: "Win32_BIOS", Vendor: hf, Version: hf, ReleaseDate: windowshardware.Field{Quality: "empty"}, SerialNumber: sf}
		s.Chassis = windowshardware.Chassis{Quality: "observed", Source: "Win32_SystemEnclosure", SerialNumber: sf}
		return s, e
	})
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err = appendWindowsStorageContext(ctx, m, f, storageConsentFixture(m), storageSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err = appendWindowsSecurityCoverage(ctx, m, f, coverageConsentFixture(m), coverageSourceFixture)
	if err != nil {
		t.Fatal(err)
	}

	// Fill inert disclosure padding to the exact16KiB bound after reserving the
	// new disclosure. Every prior real notice remains verbatim.
	// Reserve maximum timestamp width: appending refreshes GeneratedAt and
	// RFC3339Nano omits trailing zeros. Padding must not depend on wall-clock digits.
	maxGeneratedAt := time.Now().UTC().Truncate(time.Second).Add(999999999 * time.Nanosecond)
	f.Observation.GeneratedAt = maxGeneratedAt
	beforeNotice, _ := json.Marshal(f.Observation)
	delta := len(windowsResourceContextTelemetryPrivacy) + 1
	if len(f.Observation.Privacy) < 16 {
		delta = len(windowsResourceContextTelemetryPrivacy) + 3
	}
	remain := MaxWindowsObservationBytes - len(beforeNotice) - delta
	for i := 0; i < 3 && remain > 0; i++ {
		n := 4096 - len(f.Observation.Privacy[i])
		if n > remain {
			n = remain
		}
		f.Observation.Privacy[i] += strings.Repeat("x", n)
		remain -= n
	}
	if remain != 0 {
		t.Fatal("fixture observation bound", remain)
	}
	f, raw, err = appendWindowsResourceContext(ctx, m, f, resourceConsentFixture(m), maximumResourceSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	// Finish the synthetic maximum at the same width after the real append.
	// This is fixture data, not a change to runtime clocks or retry bytes.
	f.Observation.GeneratedAt = maxGeneratedAt
	raw, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	observationRaw, _ := json.Marshal(f.Observation)
	if len(observationRaw) != MaxWindowsObservationBytes {
		t.Fatal("observation not maximum", len(observationRaw))
	}
	if f.WindowsResourceContext == nil || len(f.WindowsResourceContext.Processors.Rows) != 4 {
		t.Fatal("resource clipped")
	}
	t.Logf("actual composed max observation frame %d/%d bytes; preview %d/%d bytes", len(raw), MaxFrameBytes, len(reservedRaw), windowsResourceContextBaseBytes)
	if f.WindowsSecurityCoverage == nil || f.WindowsHardwareContext == nil {
		t.Fatal("security coverage envelope omitted")
	}
	if f.WindowsUpdates == nil || f.WindowsPatchContext == nil || f.WindowsSecurityPosture == nil || f.WindowsSessionContext == nil {
		t.Fatal("frame fitting omitted a granted context envelope")
	}
	after, _ := json.Marshal(f.WindowsInventory)
	if len(raw) > MaxFrameBytes || !bytes.Equal(base, after) || f.WindowsServiceStartup.ServicesSHA256 != digest || !f.WindowsSessionContext.CollectedAt.Equal(capture) || *f.WindowsSessionContext.Sessions.ObservedCount != 32 || f.WindowsSessionContext.Sessions.RetainedCount+*f.WindowsSessionContext.Sessions.TruncatedCount != 32 {
		t.Fatal("budget lost original capture/binding")
	}
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	self := false
	for _, v := range f.WindowsProcessMetrics.Rows {
		if v.PID == 7 {
			self = true
		}
	}
	if !self {
		t.Fatal("protected self metric trimmed")
	}
}

func maximumResourceSourceFixture(_ context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
	s := windowsresourcecontext.Empty(r, windowsresourcecontext.ErrUnsupported.Error())
	name, arch := strings.Repeat("&", 128), "PowerPC"
	s.Processors = windowsresourcecontext.Processors{Quality: "partial", Reason: windowsresourcecontext.ErrPartial.Error(), Source: "Win32_Processor", Rows: []windowsresourcecontext.Processor{}}
	for i := 0; i < 4; i++ {
		s.Processors.Rows = append(s.Processors.Rows, windowsresourcecontext.Processor{Name: windowsresourcecontext.Field{Value: &name, Quality: "observed"}, Architecture: windowsresourcecontext.Field{Value: &arch, Quality: "observed"}, Cores: windowsresourcecontext.CountField{Quality: "unavailable"}, LogicalProcessors: windowsresourcecontext.CountField{Quality: "unavailable"}})
	}
	pageSize, big, max := "1073741824", "18446744072635809792", "18446744073709551615"
	count := uint32(32)
	s.Memory = windowsresourcecontext.Memory{Quality: "observed", Source: "K32GetPerformanceInfo", CommitTotalBytes: &big, CommitLimitBytes: &big, PhysicalTotalBytes: &big, PhysicalAvailableBytes: &big, PageSizeBytes: &pageSize}
	s.Pagefiles = windowsresourcecontext.Pagefiles{Quality: "observed", Source: "EnumPageFilesW", Count: &count, TotalBytes: &max, TotalInUseBytes: &max}
	return s, windowsresourcecontext.Validate(s)
}

// Conservative per-envelope limits cover canonical finite values and full JSON
// escaping, not a sum of ordinary native fixture sizes. Full event/hardware
// envelopes are untouched; row-bearing optional siblings may truthfully shrink.
// Field-by-field canonical upper bounds (including maximum timestamp width,
// finite failure tokens, numeric widths and six-byte escaped label units) are:
// security850, sessions2062, patch807, volumes399, protected-self process451,
// network339, startup375, updates502, adapters333, storage605, coverage525,
// outer framing444 bytes. Their allowances below deliberately round upward.
// The preceding actual pipeline regression exercises maximum observation bytes,
// escaped fixed labels and mixed resource failures; this test guards the sum.
func TestWindowsResourceComposedEnvelopeProof(t *testing.T) {
	pieces := map[string]int{"base": windowsResourceContextBaseBytes, "observation": MaxWindowsObservationBytes, "events": 6 << 10, "hardware": 6 << 10, "security": 1024, "patch-min": 1536, "sessions-min": 2304, "volumes-min": 512, "process-self-min": 768, "network-min": 512, "startup-min": 512, "updates-min": 768, "adapter-min": 512, "storage-min": 768, "coverage-min": 768, "outer": 1024, "resource": windowsresourcecontext.MaxBytes}
	total := 0
	for _, n := range pieces {
		total += n
	}
	if total != 73472 || total > MaxFrameBytes {
		t.Fatal("composition bound", total)
	}
	t.Logf("conservative composed envelope %d <= %d", total, MaxFrameBytes)
}
