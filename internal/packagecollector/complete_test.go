package packagecollector

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"strings"
	"sync/atomic"
	"testing"
)

func completeFixtureRows(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "Package: package-%06d\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\n\n", i)
	}
	return b.String()
}
func TestCompleteInventoryBeyondSelectedRows(t *testing.T) {
	p := healthyProvider()
	p.sources[1].r = strings.NewReader(completeFixtureRows(517))
	got, err := collectCompleteWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
	if err != nil || len(got.Rows) != 517 || !got.CollectedAt.Equal(collectedAt) || p.closed != 1 || p.sources[0].closes != 1 || p.sources[1].closes != 1 {
		t.Fatal("full source lost rows, time or cleanup")
	}
	manifest, chunks, err := fullinventory.Build(context.Background(), got, err)
	if err != nil || manifest.ObservedCount != 517 || manifest.InstalledCount != 517 || len(chunks) <= 1 {
		t.Fatal("full chunks do not cover source")
	}
	q := healthyProvider()
	q.sources[1].r = strings.NewReader(completeFixtureRows(517))
	old := runInert(t, q)
	if len(old.Inventory.Items) > 128 || !old.Inventory.Truncated || old.Inventory.Complete || old.Inventory.ObservedCount == nil || *old.Inventory.ObservedCount != 517 {
		t.Fatal("old bounded export changed")
	}
}
func TestCompleteInventoryZeroRowsVersusEmptySource(t *testing.T) {
	for _, tc := range []struct {
		input   string
		success bool
	}{{"Package: residual-package\nStatus: deinstall ok config-files\n\n", true}, {"", false}} {
		p := healthyProvider()
		p.sources[1].r = strings.NewReader(tc.input)
		got, err := collectCompleteWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
		if tc.success {
			if err != nil || got.Rows == nil || len(got.Rows) != 0 {
				t.Fatal("valid residual-only source was not complete empty")
			}
		} else if err == nil || got.Rows != nil {
			t.Fatal("empty raw source became a complete inventory")
		}
	}
}
func TestCompleteInventoryReleaseUnavailableIsNotSourceTrust(t *testing.T) {
	p := healthyProvider()
	p.errs[releaseSource] = sourceFailure(linuxpackages.ReasonPermissionDenied)
	got, err := collectCompleteWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
	if err != nil || len(got.Rows) != 2 || got.Release.Quality != linuxpackages.Denied || got.Release.Fields.ID != nil {
		t.Fatal("independent release coverage lost")
	}
	m, _, err := fullinventory.Build(context.Background(), got, err)
	if err != nil || m.Release.Quality != linuxpackages.Denied {
		t.Fatal("complete dpkg scope fabricated release authority")
	}
}
func TestCompleteInventoryFailureNeverReturnsPrefix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*inertProvider)
		reason linuxpackages.Reason
	}{
		{"release_changed", func(p *inertProvider) { p.sources[0].onCheck = func(int) error { return changedForTest() } }, linuxpackages.ReasonSourceChanged},
		{"inventory_changed", func(p *inertProvider) { p.sources[1].onCheck = func(int) error { return changedForTest() } }, linuxpackages.ReasonSourceChanged},
		{"denied", func(p *inertProvider) { p.errs[1] = sourceFailure(linuxpackages.ReasonPermissionDenied) }, linuxpackages.ReasonPermissionDenied},
		{"malformed_after_valid_rows", func(p *inertProvider) {
			p.sources[1].r = strings.NewReader(completeFixtureRows(300) + "BROKEN private diagnostic\n")
		}, linuxpackages.ReasonInvalidSource},
		{"raw_private_error", func(p *inertProvider) { p.errs[1] = errors.New("private diagnostic") }, linuxpackages.ReasonReadFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := healthyProvider()
			tc.edit(p)
			got, err := collectCompleteWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
			if !errors.Is(err, ErrCompleteSource) || got.Rows != nil || CompleteFailureReason(err) != tc.reason || strings.Contains(err.Error(), "private") {
				t.Fatal("failure exposed prefix or diagnostics")
			}
		})
	}
}
func TestCompleteInventoryCancellationAndSharedAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := healthyProvider()
	p.sources[1].onRead = cancel
	got, err := collectCompleteWith(ctx, generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
	if got.Rows != nil || CompleteFailureReason(err) != linuxpackages.ReasonTimeout || p.closed != 1 {
		t.Fatal("cancellation did not close source and discard rows")
	}
	slot := &atomic.Bool{}
	slot.Store(true)
	opened := false
	got, err = collectCompleteWith(context.Background(), generation, collectedAt, slot, func() (sourceProvider, error) { opened = true; return healthyProvider(), nil })
	if opened || got.Rows != nil || CompleteFailureReason(err) != linuxpackages.ReasonCollectorBusy || !slot.Load() {
		t.Fatal("busy collector bypassed shared admission")
	}
}
