package cachedupdates

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

func completeTestConsent() CompleteLocalConsent {
	return CompleteLocalConsent{SchemaVersion: CompleteConsentVersion, ExtensionVersion: CompleteSchemaVersion, Scope: CompleteScope, SenderBinding: strings.Repeat("a", 64), Acknowledged: true}
}
func completeFixture(t *testing.T, f nativeSource) (CompleteSource, error) {
	t.Helper()
	return collectCompleteWith(context.Background(), sample, at, completeTestConsent(), strings.Repeat("a", 64), &atomic.Bool{}, func() (nativeSource, error) { return f, nil })
}
func TestCompleteCollectionKeepsAll1100RowsAndOriginalPreview(t *testing.T) {
	f := fixture("debian")
	f.packages = nil
	f.candidates = map[string]string{}
	for i := 0; i < 1100; i++ {
		p := installedPackage{fmt.Sprintf("fixture-%05d", i), "amd64", "1.0-1", i%2 == 0}
		f.packages = append(f.packages, p)
		f.candidates[p.key()] = "2.0-1"
	}
	full, e := completeFixture(t, f)
	if e != nil || !full.Complete || len(full.Rows) != 1100 || full.Snapshot.CandidateCount == nil || *full.Snapshot.CandidateCount != 1100 || *full.Snapshot.HeldCount != 550 || !full.Snapshot.Truncated {
		t.Fatal("full capture lost rows", e)
	}
	if Validate(full.Snapshot) != nil || !full.Snapshot.CollectedAt.Equal(at) || !full.Snapshot.Metadata.OldestIndexModifiedAt.Equal(f.oldest) {
		t.Fatal("preview or capture age changed")
	}
	for i, row := range full.Snapshot.Items {
		if row != full.Rows[i] {
			t.Fatal("preview does not share exact capture")
		}
	}
	for i, row := range full.Rows {
		if i > 0 && full.Rows[i-1].Name >= row.Name {
			t.Fatal("full rows unordered")
		}
	}
}
func TestCompleteGrantRejectsPreviewAndUnknownVersionsBeforeSource(t *testing.T) {
	preview, _ := EncodeLocalConsent(testConsent(), strings.Repeat("a", 64))
	full, _ := EncodeCompleteLocalConsent(completeTestConsent(), strings.Repeat("a", 64))
	if _, e := DecodeCompleteLocalConsent(preview, strings.Repeat("a", 64)); e == nil {
		t.Fatal("preview became full permission")
	}
	if _, e := DecodeLocalConsent(full, strings.Repeat("a", 64)); e == nil {
		t.Fatal("full grant relabeled preview")
	}
	for _, mutate := range []func(*CompleteLocalConsent){func(c *CompleteLocalConsent) { *c = CompleteLocalConsent(testConsent()) }, func(c *CompleteLocalConsent) { c.Acknowledged = false }, func(c *CompleteLocalConsent) { c.Scope += "-future" }, func(c *CompleteLocalConsent) { c.SenderBinding = strings.Repeat("b", 64) }} {
		c := completeTestConsent()
		mutate(&c)
		called := false
		_, e := collectCompleteWith(context.Background(), sample, at, c, strings.Repeat("a", 64), &atomic.Bool{}, func() (nativeSource, error) { called = true; return fixture("debian"), nil })
		if e == nil || called {
			t.Fatal("unconsented full source access")
		}
	}
}

type failedCompleteRecheck struct{ *fixtureSource }

func (f failedCompleteRecheck) recheck(context.Context) error {
	return sourceFailure(ReasonSourceChanged)
}
func TestCompleteFailureNeverReturnsPrefixOrSuccessfulZero(t *testing.T) {
	full, e := completeFixture(t, failedCompleteRecheck{fixture("ubuntu")})
	if e == nil || full.Complete || full.Rows != nil || full.Snapshot.Coverage != "unavailable" || full.Snapshot.CandidateCount != nil {
		t.Fatal("failed operation promoted prefix")
	}
	f := fixture("ubuntu")
	f.candidates = map[string]string{}
	full, e = completeFixture(t, f)
	if e != nil || !full.Complete || full.Rows == nil || len(full.Rows) != 0 || *full.Snapshot.UnknownCount != 2 || full.Snapshot.Reason != ReasonCandidateUnknown {
		t.Fatal("unknown comparisons became known zero", e)
	}
	f.candidates = map[string]string{"curl:amd64": "1:8.14.1-2", "held-package:amd64": "2.0~rc1-1"}
	full, e = completeFixture(t, f)
	if e != nil || !full.Complete || full.Rows == nil || len(full.Rows) != 0 || *full.Snapshot.UnknownCount != 0 || full.Snapshot.Coverage != "complete" {
		t.Fatal("known zero not distinct", e)
	}
}
