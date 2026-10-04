package packagecollector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/linuxpackages"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const generation = "sample_0123456789abcdef0123456789abcdef"

var collectedAt = time.Date(2026, 10, 4, 1, 2, 3, 0, time.UTC)

const releaseText = "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n"
const statusText = "Package: zz-package\nStatus: install ok installed\nVersion: 1:2.0-1+b1\nArchitecture: amd64\nSource: source-package (1:2.0-1)\n\nPackage: aa-package\nStatus: install ok unpacked\nVersion: 1.0\nArchitecture: arm64\n\nPackage: residual-package\nStatus: deinstall ok config-files\n\n"

type inertSource struct {
	r                     io.Reader
	checks, reads, closes int
	onRead                func()
	onCheck               func(int) error
}

func (s *inertSource) Read(p []byte) (int, error) {
	s.reads++
	if s.onRead != nil {
		s.onRead()
	}
	return s.r.Read(p)
}
func (s *inertSource) recheck() error {
	s.checks++
	if s.onCheck != nil {
		return s.onCheck(s.checks)
	}
	return nil
}
func (s *inertSource) close() { s.closes++ }

type inertProvider struct {
	sources [2]*inertSource
	errs    [2]error
	opens   []sourceKind
	closed  int
	onOpen  func(sourceKind)
}

func healthyProvider() *inertProvider {
	return &inertProvider{sources: [2]*inertSource{{r: strings.NewReader(releaseText)}, {r: strings.NewReader(statusText)}}}
}
func (p *inertProvider) open(k sourceKind) (source, error) {
	p.opens = append(p.opens, k)
	if p.onOpen != nil {
		p.onOpen(k)
	}
	if p.errs[k] != nil {
		return nil, p.errs[k]
	}
	return p.sources[k], nil
}
func (p *inertProvider) close() { p.closed++ }
func runInert(t *testing.T, p *inertProvider) linuxpackages.Snapshot {
	t.Helper()
	s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return p, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := linuxpackages.Validate(s); err != nil {
		t.Fatal(err)
	}
	return s
}
func assertUnavailable(t *testing.T, s linuxpackages.Snapshot, release bool, reason linuxpackages.Reason) {
	t.Helper()
	if release {
		if s.Release.Reason != reason || s.Release.Fields.ID != nil || s.Release.Fields.VersionID != nil || s.Release.Fields.VersionCodename != nil || s.Release.Quality != quality(reason) {
			t.Fatalf("release: %+v", s.Release)
		}
	} else {
		x := s.Inventory
		if x.Reason != reason || x.Quality != quality(reason) || x.Items == nil || len(x.Items) != 0 || x.ObservedCount != nil || x.InstalledCount != nil || x.Complete || x.Truncated || x.CountExact {
			t.Fatalf("inventory: %+v", x)
		}
	}
}
func TestValidCallerBeforeAnyProviderWork(t *testing.T) {
	for _, tc := range []struct {
		name, generation string
		at               time.Time
		ctx              context.Context
	}{
		{"bad-generation", "sample_BAD", collectedAt, context.Background()},
		{"zero-time", generation, time.Time{}, context.Background()},
		{"non-utc", generation, collectedAt.In(time.FixedZone("different", 0)), context.Background()},
		{"old-time", generation, time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC), context.Background()},
		{"nil-context", generation, collectedAt, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			s, err := collectWith(tc.ctx, tc.generation, tc.at, &atomic.Bool{}, func() (sourceProvider, error) { called = true; return nil, nil })
			if called || err != errInvalidInput || s.SchemaVersion != "" {
				t.Fatalf("called=%v err=%v snapshot=%+v", called, err, s)
			}
		})
	}
}
func TestHealthyIndependentSourceCountsAndSelectedFields(t *testing.T) {
	p := healthyProvider()
	s := runInert(t, p)
	if s.GenerationID != generation || s.CollectedAt != collectedAt || s.Release.Fields.Target() != linuxpackages.Debian13 || s.Inventory.Quality != linuxpackages.Healthy || *s.Inventory.ObservedCount != 2 || *s.Inventory.InstalledCount != 1 || !s.Inventory.Complete {
		t.Fatalf("%+v", s)
	}
	if s.Inventory.Items[0].Name != "aa-package" || s.Inventory.Items[1].SourceVersion != "1:2.0-1" || s.Inventory.Items[1].Version != "1:2.0-1+b1" {
		t.Fatalf("%+v", s.Inventory.Items)
	}
	for _, src := range p.sources {
		if src.checks != 2 || src.closes != 1 {
			t.Fatalf("checks=%d closes=%d", src.checks, src.closes)
		}
	}
	if p.closed != 1 || len(p.opens) != 2 {
		t.Fatal("resources not closed")
	}
}
func TestFailureReasonsClearOnlyAffectedSource(t *testing.T) {
	for _, reason := range []linuxpackages.Reason{linuxpackages.ReasonSourceMissing, linuxpackages.ReasonPermissionDenied, linuxpackages.ReasonInvalidSource, linuxpackages.ReasonReadFailed, linuxpackages.ReasonSourceChanged} {
		for _, kind := range []sourceKind{releaseSource, inventorySource} {
			t.Run(fmt.Sprintf("%s/%d", reason, kind), func(t *testing.T) {
				p := healthyProvider()
				p.errs[kind] = sourceFailure(reason)
				s := runInert(t, p)
				assertUnavailable(t, s, kind == releaseSource, reason)
				if kind == releaseSource && s.Inventory.Quality != linuxpackages.Healthy || kind == inventorySource && s.Release.Quality != linuxpackages.Healthy {
					t.Fatal("unrelated source was cleared")
				}
			})
		}
	}
}
func TestMalformedLimitsAndReadFailuresNeverExportPrefixOrDiagnostic(t *testing.T) {
	secret := errors.New("PRIVATE /secret/path credential-content")
	for _, tc := range []struct {
		name   string
		kind   sourceKind
		r      io.Reader
		reason linuxpackages.Reason
	}{
		{"release-invalid", releaseSource, strings.NewReader(releaseText + "ID=duplicate\n"), linuxpackages.ReasonInvalidSource},
		{"release-byte-cap", releaseSource, strings.NewReader(strings.Repeat("#0123456789\n", 7000)), linuxpackages.ReasonInvalidSource},
		{"release-line-cap", releaseSource, strings.NewReader("#" + strings.Repeat("x", linuxpackages.MaxOSReleaseLine)), linuxpackages.ReasonInvalidSource},
		{"release-read", releaseSource, io.MultiReader(strings.NewReader(releaseText), errReader{secret}), linuxpackages.ReasonReadFailed},
		{"dpkg-invalid", inventorySource, strings.NewReader(statusText + "Package: invalid-package\nStatus: malformed\n"), linuxpackages.ReasonInvalidSource},
		{"dpkg-empty", inventorySource, strings.NewReader(""), linuxpackages.ReasonInvalidSource},
		{"dpkg-read", inventorySource, io.MultiReader(strings.NewReader(statusText), errReader{secret}), linuxpackages.ReasonReadFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := healthyProvider()
			p.sources[tc.kind].r = tc.r
			s := runInert(t, p)
			assertUnavailable(t, s, tc.kind == releaseSource, tc.reason)
			encoded, _ := json.Marshal(s)
			if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "/secret") {
				t.Fatal("raw diagnostic escaped")
			}
		})
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
func TestUnknownProviderErrorIsFixed(t *testing.T) {
	s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) { return nil, errors.New("private diagnostic") })
	if err != nil {
		t.Fatal(err)
	}
	assertUnavailable(t, s, true, linuxpackages.ReasonReadFailed)
	assertUnavailable(t, s, false, linuxpackages.ReasonReadFailed)
}
func TestFinalRecheckAfterBothAttempts(t *testing.T) {
	for _, failedOther := range []bool{false, true} {
		t.Run(fmt.Sprint(failedOther), func(t *testing.T) {
			p := healthyProvider()
			p.sources[0].onCheck = func(check int) error {
				if check == 2 {
					if len(p.opens) != 2 {
						t.Fatal("final recheck too early")
					}
					return changedForTest()
				}
				return nil
			}
			if failedOther {
				p.sources[1].r = strings.NewReader("broken")
			}
			s := runInert(t, p)
			assertUnavailable(t, s, true, linuxpackages.ReasonSourceChanged)
			if !failedOther && s.Inventory.Quality != linuxpackages.Healthy {
				t.Fatal("inventory cleared")
			}
		})
	}
}
func changedForTest() error { return sourceFailure(linuxpackages.ReasonSourceChanged) }
func TestCooperativeCancellationCheckpoints(t *testing.T) {
	for _, point := range []string{"before", "factory", "release-read", "between", "inventory-read", "final"} {
		t.Run(point, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := healthyProvider()
			factoryCalls := 0
			if point == "before" {
				cancel()
			}
			if point == "release-read" {
				p.sources[0].onRead = cancel
			}
			if point == "between" {
				p.sources[0].onCheck = func(n int) error {
					if n == 1 {
						cancel()
					}
					return nil
				}
			}
			if point == "inventory-read" {
				p.sources[1].onRead = cancel
			}
			if point == "final" {
				p.sources[1].onCheck = func(n int) error {
					if n == 2 {
						cancel()
					}
					return nil
				}
			}
			s, err := collectWith(ctx, generation, collectedAt, &atomic.Bool{}, func() (sourceProvider, error) {
				factoryCalls++
				if point == "factory" {
					cancel()
				}
				return p, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			assertUnavailable(t, s, true, linuxpackages.ReasonTimeout)
			assertUnavailable(t, s, false, linuxpackages.ReasonTimeout)
			if point == "before" && factoryCalls != 0 {
				t.Fatal("canceled call opened provider")
			}
			if point == "factory" && len(p.opens) != 0 {
				t.Fatal("read after canceled provider")
			}
			if (point == "release-read" || point == "between") && len(p.opens) != 1 {
				t.Fatal("read second source after cancel")
			}
		})
	}
}
func TestSingleFlightRemainsHeldUntilSynchronousWorkReturns(t *testing.T) {
	var slot atomic.Bool
	entered, unblock, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := healthyProvider()
	first := true
	p.sources[0].onRead = func() {
		if first {
			first = false
			close(entered)
			<-unblock
		}
	}
	var result linuxpackages.Snapshot
	var firstErr error
	go func() {
		defer close(done)
		result, firstErr = collectWith(ctx, generation, collectedAt, &slot, func() (sourceProvider, error) { return p, nil })
	}()
	<-entered
	cancel()
	for i := 0; i < 2; i++ {
		s, err := collectWith(context.Background(), generation, collectedAt, &slot, func() (sourceProvider, error) { t.Error("busy call did provider work"); return nil, nil })
		if err != nil {
			t.Fatal(err)
		}
		assertUnavailable(t, s, true, linuxpackages.ReasonCollectorBusy)
		assertUnavailable(t, s, false, linuxpackages.ReasonCollectorBusy)
	}
	select {
	case <-done:
		t.Fatal("abandoned synchronous work")
	default:
	}
	close(unblock)
	<-done
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	assertUnavailable(t, result, false, linuxpackages.ReasonTimeout)
	if slot.Load() || p.closed != 1 {
		t.Fatal("slot/resources not released")
	}
	next := healthyProvider()
	s, err := collectWith(context.Background(), generation, collectedAt, &slot, func() (sourceProvider, error) { return next, nil })
	if err != nil || s.Inventory.Quality != linuxpackages.Healthy {
		t.Fatal("slot did not recover")
	}
}
func TestFullParseThenDeterministicTrimPreservesCounts(t *testing.T) {
	var b strings.Builder
	for i := 199; i >= 0; i-- {
		fmt.Fprintf(&b, "Package: pkg-%03d\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n\n", i, "1."+strings.Repeat("9", 150))
	}
	p := healthyProvider()
	p.sources[1].r = strings.NewReader(b.String())
	s := runInert(t, p)
	if *s.Inventory.ObservedCount != 200 || *s.Inventory.InstalledCount != 200 || !s.Inventory.CountExact || !s.Inventory.Truncated || s.Inventory.Complete || len(s.Inventory.Items) > linuxpackages.MaxExportRows || s.Inventory.Reason != linuxpackages.ReasonByteLimit || s.Inventory.Items[0].Name != "pkg-000" {
		t.Fatalf("%+v", s.Inventory)
	}
	bts, _ := json.Marshal(s)
	if len(bts) > linuxpackages.MaxSnapshotBytes {
		t.Fatal("over byte cap")
	}
	for i, row := range s.Inventory.Items {
		if row.Name != fmt.Sprintf("pkg-%03d", i) {
			t.Fatal("not deterministic prefix")
		}
	}
	if cap(s.Inventory.Items) != len(s.Inventory.Items) {
		t.Fatal("omitted data retained")
	}
}
func TestResidualOnlyIsHealthyZero(t *testing.T) {
	p := healthyProvider()
	p.sources[1].r = strings.NewReader("Package: residual\nStatus: deinstall ok config-files\n\n")
	s := runInert(t, p)
	if !s.Inventory.Complete || *s.Inventory.ObservedCount != 0 || *s.Inventory.InstalledCount != 0 || len(s.Inventory.Items) != 0 {
		t.Fatalf("%+v", s.Inventory)
	}
}
func TestDurationIncludesAttempt(t *testing.T) {
	p := healthyProvider()
	p.onOpen = func(k sourceKind) {
		if k == inventorySource {
			time.Sleep(12 * time.Millisecond)
		}
	}
	s := runInert(t, p)
	if s.DurationMS < 10 {
		t.Fatal("duration excludes actual reads")
	}
}

// repeatReader emits synthetic ignored-field continuations without allocating
// an over-cap file or consulting any machine source.
type repeatReader struct {
	data   string
	offset int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.data[r.offset]
		r.offset = (r.offset + 1) % len(r.data)
	}
	return len(p), nil
}
func TestDpkgBoundedReadRejectsOversizedValidPrefix(t *testing.T) {
	p := healthyProvider()
	p.sources[1].r = io.MultiReader(strings.NewReader(statusText+"Package: oversized\nStatus: deinstall ok config-files\nDescription: ignored\n"), io.LimitReader(&repeatReader{data: " " + strings.Repeat("x", 4094) + "\n"}, linuxpackages.MaxDpkgBytes))
	s := runInert(t, p)
	assertUnavailable(t, s, false, linuxpackages.ReasonInvalidSource)
}

func TestCancellationDuringFailingProviderConstruction(t *testing.T) {
	for _, reason := range []linuxpackages.Reason{linuxpackages.ReasonPermissionDenied, linuxpackages.ReasonReadFailed, linuxpackages.ReasonNotSupported} {
		t.Run(string(reason), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var slot atomic.Bool
			s, err := collectWith(ctx, generation, collectedAt, &slot, func() (sourceProvider, error) { cancel(); return nil, sourceFailure(reason) })
			if err != nil {
				t.Fatal(err)
			}
			assertUnavailable(t, s, true, linuxpackages.ReasonTimeout)
			assertUnavailable(t, s, false, linuxpackages.ReasonTimeout)
			if slot.Load() {
				t.Fatal("slot not released after failed construction")
			}
		})
	}
}
