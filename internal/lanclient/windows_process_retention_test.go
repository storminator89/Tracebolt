//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
)

const retentionFixtureSelf = uint32(65532)

func retentionReport(at time.Time, self uint32, full bool) windowsinventory.Report {
	r := syntheticWindowsReport(at)
	r.Processes.Rows = nil
	for i := 0; i < 127; i++ {
		pid := uint32(1000 + 4*i)
		if i == 0 {
			pid = 0
		}
		// Avoid an accidental collision with the real test process PID.
		if pid == self {
			pid++
		}
		r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: pid, Name: "fixture-process-name.exe", Threads: 1})
	}
	r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: self, Name: "fixture-agent.exe", Threads: 1})
	if full {
		r.Services.Rows = nil
		r.Services.Quality, r.Services.Complete = "healthy", true
		for i := 0; i < 64; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("s", 60), DisplayName: "Fixture", State: "running", PID: 7})
		}
		r.Software.Rows = nil
		r.Software.Quality, r.Software.Complete = "healthy", true
		for i := 0; i < 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("<", 250), RegistryView: "64"})
		}
	}
	return r
}

func retentionMetricSource(t *testing.T, ctx context.Context, f frame) windowsprocessmetrics.Snapshot {
	t.Helper()
	self := processMetricSelfPID(ctx)
	sampler := windowsprocessmetrics.NewSamplerWithReader(func(_ context.Context, pid uint32) windowsprocessmetrics.Reading {
		if pid == self {
			return windowsprocessmetrics.Reading{Creation: 1, Memory: 10485760}
		}
		return windowsprocessmetrics.Reading{CPUErr: windowsprocessmetrics.ErrDenied}
	}, time.Now, 1)
	pids := []uint32{}
	for _, row := range f.WindowsInventory.Processes.Rows {
		pids = append(pids, row.PID)
	}
	s, err := nativeProcessMetricCollector(sampler)(ctx, pids, f.WindowsInventory.GenerationID, strings.Repeat("e", 32), f.WindowsInventory.CollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func retentionFullFrame(t *testing.T, m Material, ctx context.Context) frame {
	t.Helper()
	f, _, err := collectWindowsFrame(ctx, m.config, 1, func(ctx context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		return windowsmanaged.FromReportForProcessMetrics(retentionReport(time.Now().UTC(), retentionFixtureSelf, true), g, processMetricSelfPID(ctx))
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 3700), strings.Repeat("b", 3700), strings.Repeat("c", 3700)}
	if len(f.WindowsInventory.Processes.Rows) != 128 {
		t.Fatal("fixture lost process rows at inventory stage")
	}
	return f
}

func assertRetentionFrame(t *testing.T, m Material, f frame, raw []byte, original windowsprocessmetrics.Snapshot) {
	t.Helper()
	if len(raw) > MaxFrameBytes || f.WindowsProcessMetrics == nil {
		t.Fatal("frame budget or metric absence")
	}
	if _, err := decodeFrameForConfig(raw, f.Sequence, m.config); err != nil {
		t.Fatal(err)
	}
	if _, err := lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s := f.WindowsProcessMetrics
	if s.ObservedCount != original.ObservedCount || !s.CollectedAt.Equal(original.CollectedAt) || s.GrantID != original.GrantID || !s.Truncated {
		t.Fatal("refit changed count/capture/grant")
	}
	found := false
	for _, row := range s.Rows {
		if row.PID == retentionFixtureSelf {
			found = true
			if row.CPUQuality != "first-sample" || row.CPUPercent != nil || row.MemoryBytes == nil || *row.MemoryBytes != "10485760" {
				t.Fatal("refit promoted or lost self values")
			}
		}
	}
	if !found {
		t.Fatal("downstream refit dropped self")
	}
}

func TestSelfRetentionAllFrameRefits(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), retentionFixtureSelf)
	f := retentionFullFrame(t, m, ctx)
	inventoryBefore, _ := json.Marshal(f.WindowsInventory)
	original := retentionMetricSource(t, ctx, f)
	f, raw, err := appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		return original, nil
	})
	if err != nil {
		t.Fatal("process frame fit", err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	if len(f.WindowsProcessMetrics.Rows) >= len(original.Rows) {
		t.Fatal("fixture did not exercise process whole-frame trim", len(original.Rows), len(f.WindowsProcessMetrics.Rows))
	}
	before := len(f.WindowsProcessMetrics.Rows)
	f, raw, err = appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkSourceFixture)
	if err != nil {
		t.Fatal("network refit", err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	if len(f.WindowsProcessMetrics.Rows) >= before {
		t.Fatal("fixture did not exercise network sibling trim")
	}
	before = len(f.WindowsProcessMetrics.Rows)
	f, raw, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal("startup refit", err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	if len(f.WindowsProcessMetrics.Rows) >= before {
		t.Fatal("fixture did not exercise startup sibling trim")
	}
	inventoryAfter, _ := json.Marshal(f.WindowsInventory)
	if !bytes.Equal(inventoryBefore, inventoryAfter) {
		t.Fatal("sibling fitting mutated inventory")
	}
}

func TestSelfRetentionStartupSkipsProtectedOnlyMetrics(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), retentionFixtureSelf)
	f := retentionFullFrame(t, m, ctx)
	original := retentionMetricSource(t, ctx, f)
	minimal := minimumProcessMetricSnapshot(original, retentionFixtureSelf)
	f, _, err := appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		return minimal, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := networkSourceFixture(ctx, f.WindowsInventory.GenerationID, networkConsentFixture(m).GrantID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	row := n.Rows[0]
	n.Rows = nil
	for i := 0; i < 64; i++ {
		r := row
		r.LocalPort = uint16(1000 + i)
		n.Rows = append(n.Rows, r)
	}
	n.ObservedCount = 64
	n, err = windowsnetwork.FitBudget(n, windowsnetwork.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error) { return n, nil })
	if err != nil {
		t.Fatal(err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	before := len(f.WindowsNetwork.Rows)
	if before == 0 || before >= len(n.Rows) {
		t.Fatal("fixture did not fill network frame budget", before, len(n.Rows))
	}
	f, raw, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal("protected-only metric incorrectly blocked removable network", err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	if len(f.WindowsProcessMetrics.Rows) != 1 || len(f.WindowsNetwork.Rows) >= before || !f.WindowsNetwork.CollectedAt.Equal(n.CollectedAt) || f.WindowsNetwork.ObservedCount != n.ObservedCount {
		t.Fatal("did not preserve self and trim network honestly")
	}
}

func TestSelfRetentionFreshConsentAndExactPendingRetry(t *testing.T) {
	for _, consentState := range []string{"enabled", "disabled", "invalid", "absent"} {
		t.Run(consentState, func(t *testing.T) {
			m := windowsMaterialFixture(t, "http-test")
			state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			c := processConsentFixture(m)
			if consentState == "disabled" {
				c.Enabled = false
			}
			if consentState == "invalid" {
				c.SenderBinding = strings.Repeat("0", 64)
			}
			wantSelf := uint32(0)
			if consentState == "enabled" {
				wantSelf = uint32(os.Getpid())
			}
			inventoryCalls, metricReads := 0, 0
			sampler := windowsprocessmetrics.NewSamplerWithReader(func(_ context.Context, pid uint32) windowsprocessmetrics.Reading {
				metricReads++
				if metricReads == 1 && pid != wantSelf {
					t.Fatal("native seam did not sample self first")
				}
				if pid == wantSelf {
					return windowsprocessmetrics.Reading{Creation: 1, Memory: 42}
				}
				return windowsprocessmetrics.Reading{CPUErr: windowsprocessmetrics.ErrDenied}
			}, time.Now, 1)
			var bodies [][]byte
			collect := func(ctx context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
				inventoryCalls++
				if processMetricSelfPID(ctx) != wantSelf {
					t.Fatal("self policy not consent-gated")
				}
				r := retentionReport(time.Now().UTC(), uint32(os.Getpid()), false)
				s, d, err := windowsmanaged.FromReportForProcessMetrics(r, generation, processMetricSelfPID(ctx))
				if wantSelf == 0 {
					legacy, _, e := windowsmanaged.FromReport(r, generation)
					got, _ := json.Marshal(s)
					old, _ := json.Marshal(legacy)
					if e != nil || !bytes.Equal(got, old) {
						t.Fatal("disabled consent changed inventory bytes")
					}
				}
				return s, d, err
			}
			run := func() (Report, error) {
				return runUsingStateWithProcessMetricsDependencies(context.Background(), m, state, nil, nil, nil, collect, func(req *http.Request) (*http.Response, error) {
					b, _ := io.ReadAll(req.Body)
					bodies = append(bodies, b)
					return nil, errors.New("synthetic lost receipt")
				}, nil, nil, nil, nil, func() (windowsprocessmetrics.Consent, bool) { return c, consentState != "absent" }, nativeProcessMetricCollector(sampler))
			}
			if _, err = run(); !errors.Is(err, ErrTransport) {
				t.Fatal(err)
			}
			readBefore := metricReads
			if report, err := run(); !errors.Is(err, ErrTransport) || !report.RetriedPending {
				t.Fatal("pending not retried", err)
			}
			if inventoryCalls != 1 || metricReads != readBefore || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatal("retry reselected, recollected or changed bytes")
			}
			var sent frame
			if json.Unmarshal(bodies[0], &sent) != nil {
				t.Fatal("invalid fixture frame")
			}
			if wantSelf == 0 {
				if metricReads != 0 || sent.WindowsProcessMetrics != nil || sent.SchemaVersion != FrameWindowsInventoryVersion {
					t.Fatal("disabled scope gained reads or wire sibling")
				}
			} else {
				if metricReads != 128 || sent.WindowsProcessMetrics == nil {
					t.Fatal("missing opted-in source", metricReads)
				}
				minimum := minimumProcessMetricSnapshot(*sent.WindowsProcessMetrics, wantSelf)
				if len(minimum.Rows) != 1 || minimum.Rows[0].MemoryBytes == nil || *minimum.Rows[0].MemoryBytes != "42" {
					t.Fatal("sender lost readable self")
				}
			}
		})
	}
}

func TestSelfRetentionProcessReservesSelfAlongsideFullVolumeFrame(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), retentionFixtureSelf)
	f := retentionFullFrame(t, m, ctx)
	original := retentionMetricSource(t, ctx, f)
	v, err := volumeSourceFixture(ctx, f.WindowsInventory.GenerationID, volumeConsentFixture(m), m.binding)
	if err != nil {
		t.Fatal(err)
	}
	v.Rows = nil
	v.ObservedCount, v.Complete, v.Truncated, v.Quality = 64, false, true, "bounded"
	for i := 0; i < 40; i++ {
		v.Rows = append(v.Rows, windowsvolumes.Volume{VolumeID: fmt.Sprintf(`\\?\Volume{11111111-2222-3333-4444-%012x}\`, i), DriveType: "fixed", Quality: "observed", Capacity: &windowsvolumes.Capacity{TotalBytes: "18446744073709551615", FreeBytes: "18446744073709551615", AvailableBytes: "18446744073709551615"}})
	}
	f, _, err = appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error) {
		return v, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.WindowsVolumes.Rows)
	if before == 0 || before >= len(v.Rows) {
		t.Fatal("fixture did not fill frame with volume rows", before, len(v.Rows))
	}
	f, raw, err := appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		return original, nil
	})
	if err != nil {
		t.Fatal("did not reclaim enough space for self and metric envelope", err)
	}
	assertRetentionFrame(t, m, f, raw, original)
	if len(f.WindowsVolumes.Rows) >= before || f.WindowsVolumes.ObservedCount != v.ObservedCount || !f.WindowsVolumes.CollectedAt.Equal(v.CollectedAt) {
		t.Fatal("volume refit did not preserve truth")
	}
}
