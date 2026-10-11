//go:build linux

package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"strings"
	"testing"
	"time"
)

func TestWindowsEarlierOptionalBudgetEnvelopesKeepCurrentBindings(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, startupWindowsSource)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := withProcessMetricSelfPID(parent, f.WindowsInventory.Processes.Rows[0].PID)
	at := f.WindowsInventory.CollectedAt
	// Less than the real three-second send reserve: every wrapper must skip its
	// provider and retain a current-grant unavailable envelope, including self.
	f, _, err = appendWindowsEvents(ctx, m, f, eventConsentFixture(m), eventsWithPrimaryReserve(func(context.Context, string, windowseventhealth.Consent, string) (windowseventhealth.Snapshot, error) {
		t.Fatal("events read after reserve")
		return windowseventhealth.Snapshot{}, nil
	}, at))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), volumesWithPrimaryReserve(func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error) {
		t.Fatal("volumes read after reserve")
		return windowsvolumes.Snapshot{}, nil
	}, at))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), processMetricsWithPrimaryReserve(func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		t.Fatal("process read after reserve")
		return windowsprocessmetrics.Snapshot{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkWithPrimaryReserve(func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error) {
		t.Fatal("network read after reserve")
		return windowsnetwork.Snapshot{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupWithPrimaryReserve(func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		t.Fatal("startup read after reserve")
		return windowsmanaged.ServiceStartupSnapshot{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsAdapterContext(ctx, m, f, adapterConsentFixture(m), adapterContextWithPrimaryReserve(func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) {
		t.Fatal("adapter read after reserve")
		return windowsadapters.Snapshot{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if f.WindowsEvents.Channels[0].Quality != "unavailable" || f.WindowsVolumes.Quality != "unavailable" || f.WindowsNetwork.Quality != "unavailable" || f.WindowsAdapterContext.Quality != "unavailable" {
		t.Fatal("budget became healthy empty")
	}
	if len(f.WindowsProcessMetrics.Rows) != len(f.WindowsInventory.Processes.Rows) || f.WindowsProcessMetrics.Rows[0].CPUQuality != "unavailable" || f.WindowsProcessMetrics.Rows[0].MemoryQuality != "unavailable" {
		t.Fatal("current PID/self binding lost")
	}
	digest, _ := windowsmanaged.ServiceStartupRowsSHA256(f.WindowsInventory.Services.Rows)
	if f.WindowsServiceStartup.ServicesSHA256 != digest || int(f.WindowsServiceStartup.RequestedCount) != len(f.WindowsInventory.Services.Rows) {
		t.Fatal("current service-row binding lost")
	}
	for _, row := range f.WindowsServiceStartup.Rows {
		if row.StartupQuality != "unavailable" || row.DelayedAutoQuality != "unavailable" {
			t.Fatal("startup budget became observed")
		}
	}
	sentinel := errors.New("fixture source failure")
	if _, err := windowsOptionalSource(context.Background(), func(context.Context) (int, error) { return 0, sentinel }, func() (int, error) { return 1, nil }); !errors.Is(err, sentinel) {
		t.Fatal("source error hidden", err)
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	if _, err := windowsOptionalSource(stopped, func(context.Context) (int, error) { t.Fatal("capture after cancellation"); return 0, nil }, func() (int, error) { t.Fatal("cancellation downgraded"); return 0, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestWindowsOptionalMaximumRowBudgetFallbacksAreValid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	generation, grant, at := "sample_"+strings.Repeat("1", 32), strings.Repeat("2", 32), time.Now().UTC()
	t.Run("processes", func(t *testing.T) {
		pids := make([]uint32, 128)
		for i := range pids {
			pids[i] = uint32(i + 1)
		}
		s, e := processMetricsWithPrimaryReserve(func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
			t.Fatal("unexpected source read")
			return windowsprocessmetrics.Snapshot{}, nil
		})(withProcessMetricSelfPID(ctx, 128), pids, generation, grant, at)
		raw, _ := json.Marshal(s)
		valid := windowsprocessmetrics.Validate(s)
		t.Logf("rows=%d encodedBytes=%d maxBytes=%d sourceError=%v validate=%v", len(s.Rows), len(raw), windowsprocessmetrics.MaxBytes, e, valid)
		if e != nil || valid != nil {
			t.Fatal("budget fallback rejects an admitted 128-PID base")
		}
		if s.ObservedCount != 128 || !s.Truncated || len(s.Rows) == 0 || s.Rows[len(s.Rows)-1].PID != 128 || s.GrantID != grant || s.GenerationID != generation || !s.CollectedAt.Equal(at) {
			t.Fatal("process fallback lost count, self, or original binding")
		}
		for _, row := range s.Rows {
			if row.CPUQuality != "unavailable" || row.MemoryQuality != "unavailable" {
				t.Fatal("invented process measurement")
			}
		}
	})
	t.Run("services", func(t *testing.T) {
		rows := make([]windowsmanaged.Service, 128)
		for i := range rows {
			rows[i] = windowsmanaged.Service{Name: fmt.Sprintf("fixture-service-%03d", i), DisplayName: "fixture", State: "running", PID: uint32(i + 1)}
		}
		s, e := serviceStartupWithPrimaryReserve(func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
			t.Fatal("unexpected source read")
			return windowsmanaged.ServiceStartupSnapshot{}, nil
		})(ctx, rows, generation, grant, at)
		raw, _ := json.Marshal(s)
		valid := windowsmanaged.ValidateServiceStartup(s)
		t.Logf("rows=%d encodedBytes=%d maxBytes=%d sourceError=%v validate=%v", len(s.Rows), len(raw), windowsmanaged.ServiceStartupMaxBytes, e, valid)
		if e != nil || valid != nil {
			t.Fatal("budget fallback rejects an admitted 128-service base")
		}
		digest, _ := windowsmanaged.ServiceStartupRowsSHA256(rows)
		if s.RequestedCount != 128 || !s.Truncated || len(s.Rows) == 0 || s.ServicesSHA256 != digest || s.GrantID != grant || s.GenerationID != generation || !s.CollectedAt.Equal(at) {
			t.Fatal("startup fallback lost count, digest or original binding")
		}
		for i, row := range s.Rows {
			if row.ServiceIndex != uint32(i) || row.StartupQuality != "unavailable" || row.DelayedAutoQuality != "unavailable" {
				t.Fatal("startup fallback rebound row")
			}
		}
	})
}
