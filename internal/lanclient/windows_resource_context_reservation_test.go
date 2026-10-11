//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourcecontext"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowsResourceContextRuntimeReservesBeforeBindingAndNeverRefitsRetry(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	calls, metricsCalls, startupCalls := 0, 0, 0
	var captured windowsmanaged.Snapshot
	var bodies [][]byte
	collect := func(ctx context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		calls++
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		r.Services.Quality, r.Services.Complete = "healthy", true
		r.Software.Quality, r.Software.Complete = "healthy", true
		self := uint32(os.Getpid())
		for i := uint32(1); i <= 128; i++ {
			if i == self {
				continue
			}
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: i, Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: self, Name: "self", Threads: 1})
		for i := 0; i < 128; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("x", 60), DisplayName: "Fixture", State: "running", PID: 7})
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		s, d, e := windowsmanaged.FromReportForProcessMetrics(r, g, self)
		captured = s
		return s, d, e
	}
	var boundPIDs []uint32
	var boundDigest string
	metricCollect := func(ctx context.Context, pids []uint32, g, grant string, at time.Time) (windowsprocessmetrics.Snapshot, error) {
		metricsCalls++
		boundPIDs = append([]uint32{}, pids...)
		return processSourceFixture(ctx, pids, g, grant, at)
	}
	startupCollect := func(ctx context.Context, rows []windowsmanaged.Service, g, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		startupCalls++
		boundDigest, _ = windowsmanaged.ServiceStartupRowsSHA256(rows)
		return serviceStartupSourceFixture(ctx, rows, g, grant, at)
	}
	send := func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, b)
		return nil, errors.New("fixture offline")
	}
	run := func() (Report, error) {
		return runUsingStateWithResourceContextAuthorityDependencies(context.Background(), m, state, nil, nil, nil, collect, send,
			nil, nil, nil, nil, func() (windowsprocessmetrics.Consent, bool) { return processConsentFixture(m), true }, metricCollect, nil, nil, func() (windowsmanaged.ServiceStartupConsent, bool) { return serviceStartupConsentFixture(m), true }, startupCollect,
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsresourcecontext.Consent, bool) { return resourceConsentFixture(m), true }, resourceSourceFixture, func() bool { return true })
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	var f frame
	if json.Unmarshal(bodies[0], &f) != nil {
		t.Fatal("frame")
	}
	base, _ := json.Marshal(f.WindowsInventory)
	original, _ := json.Marshal(captured)
	if len(base) > windowsResourceContextBaseBytes || len(original) <= windowsResourceContextBaseBytes || f.WindowsInventory.Processes.ObservedCount != captured.Processes.ObservedCount || f.WindowsInventory.Services.ObservedCount != captured.Services.ObservedCount || !f.WindowsInventory.CollectedAt.Equal(captured.CollectedAt) || len(boundPIDs) != len(f.WindowsInventory.Processes.Rows) || boundDigest != f.WindowsServiceStartup.ServicesSHA256 {
		t.Fatal("reservation or binding lost")
	}
	selfPresent := false
	for i, row := range f.WindowsInventory.Processes.Rows {
		if boundPIDs[i] != row.PID {
			t.Fatal("post-binding trim")
		}
		selfPresent = selfPresent || row.PID == uint32(os.Getpid())
	}
	if !selfPresent {
		t.Fatal("self removed")
	}
	report, e := run()
	if !errors.Is(e, ErrTransport) || !report.RetriedPending || calls != 1 || metricsCalls != 1 || startupCalls != 1 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry recollected or refitted", report, e, calls, metricsCalls, startupCalls)
	}
}
