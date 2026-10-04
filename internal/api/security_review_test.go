package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/offlinecatalog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type reviewCompareFunc func(context.Context, string, string) (int, error)

func (f reviewCompareFunc) Compare(c context.Context, a, b string) (int, error) { return f(c, a, b) }

func reviewPackageFixture(t *testing.T, at time.Time) enrollmentstore.PackageView {
	t.Helper()
	release, e := linuxpackages.ParseOSRelease(context.Background(), strings.NewReader("ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n"))
	if e != nil {
		t.Fatal(e)
	}
	n := uint64(1)
	snapshot := linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: "sample_" + strings.Repeat("a", 32), CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: release}, Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true, ObservedCount: &n, InstalledCount: &n, Items: []linuxpackages.PackageRow{{Name: "fixture-binary", Version: "9.0-1", Architecture: "amd64", SourcePackage: "fixture", SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}}}}
	if e := linuxpackages.Validate(snapshot); e != nil {
		t.Fatal(e)
	}
	return enrollmentstore.PackageView{SchemaVersion: "tracebolt.package-view.v1", DeviceID: "demo-linux-01", Status: "fresh", ServerNow: at, ReceivedAt: &at, Sequence: &n, MaxAgeSeconds: 120, Snapshot: &snapshot}
}
func reviewEnabled(t *testing.T) (*Server, enrollmentstore.PackageView) {
	t.Helper()
	s := setup(t)
	at := time.Now().UTC()
	view := reviewPackageFixture(t, at)
	s.aiCollectionProfile = enrollmentcrypto.CollectionProfilePackages
	s.catalogStore = offlinecatalog.New()
	s.catalogReviews = make(chan struct{}, 1)
	s.catalogNow = func() time.Time { return at }
	s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) { return view, nil }
	raw := strings.Replace(catalogFixtureJSON, `"synthetic":true`, `"synthetic":false`, 1)
	candidate, e := offlinecatalog.Parse(context.Background(), []byte(raw), at)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.catalogStore.Replace(context.Background(), s.catalogStore.View(at).Revision, candidate, at)
	if e != nil {
		t.Fatal(e)
	}
	return s, view
}
func reviewResponse(t *testing.T, s *Server) (*httptest.ResponseRecorder, securityReviewView) {
	t.Helper()
	w := request(s, "GET", "/api/devices/demo-linux-01/security/review", "", nil)
	var v securityReviewView
	if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal("invalid response")
	}
	return w, v
}
func TestConditionalReviewDefaultsAndBoundedLineage(t *testing.T) {
	s := setup(t)
	w, v := reviewResponse(t, s)
	if w.Code != 200 || v.CollectionStatus != "not_configured" || v.Review != nil {
		t.Fatal("implicit review")
	}
	if request(s, "GET", "/api/devices/missing/security/review", "", nil).Code != 404 {
		t.Fatal("unknown device")
	}
	s, source := reviewEnabled(t)
	w, v = reviewResponse(t, s)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if v.Review == nil || len(v.Review.Candidates) != 1 || v.Review.AffectedCVEs != nil || v.Review.OfferedUpdates != nil || v.Review.Candidates[0].ReportedSourceVersion != "1.0-1" || v.Review.Catalog.OriginAssurance != "unverified" || *v.Sequence != *source.Sequence || v.Review.Snapshot.GenerationID != source.Snapshot.GenerationID || w.Body.Len() > maxSecurityReviewResponseBytes {
		t.Fatal("incorrect conditional lineage")
	}
	for _, suffix := range []string{"?", "?x=1"} {
		if request(s, "GET", "/api/devices/demo-linux-01/security/review"+suffix, "", nil).Code != 400 {
			t.Fatal("query accepted")
		}
	}
	if request(s, "GET", "/api/devices/demo-linux-01/security/review", "{}", nil).Code != 400 {
		t.Fatal("body accepted")
	}
}
func TestConditionalReviewSuppressesNonfreshAndBusy(t *testing.T) {
	for _, status := range []string{"not_configured", "awaiting", "stale", "revoked", "unavailable"} {
		t.Run(status, func(t *testing.T) {
			s, source := reviewEnabled(t)
			source.Status = status
			s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) { return source, nil }
			s.reviewComparator = reviewCompareFunc(func(context.Context, string, string) (int, error) { t.Fatal("compared nonfresh source"); return 0, nil })
			w, v := reviewResponse(t, s)
			if w.Code != 200 || v.Review != nil || v.CollectionStatus != status {
				t.Fatal("nonfresh review")
			}
		})
	}
	s, _ := reviewEnabled(t)
	s.catalogReviews <- struct{}{}
	w, _ := reviewResponse(t, s)
	<-s.catalogReviews
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" || !strings.Contains(w.Body.String(), "review_busy") {
		t.Fatal("unbounded admission")
	}
	s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) {
		return enrollmentstore.PackageView{}, enrollmentstore.ErrBusy
	}
	w, _ = reviewResponse(t, s)
	if w.Code != 429 || !strings.Contains(w.Body.String(), "storage_busy") {
		t.Fatal("storage pressure misclassified")
	}
}
func TestConditionalReviewDropsChangedInputs(t *testing.T) {
	for _, kind := range []string{"catalog", "sequence", "receipt", "revoked", "snapshot", "future"} {
		t.Run(kind, func(t *testing.T) {
			s, source := reviewEnabled(t)
			var reads atomic.Int32
			s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) {
				if reads.Add(1) > 1 {
					switch kind {
					case "sequence":
						n := uint64(2)
						source.Sequence = &n
					case "receipt":
						at := source.ReceivedAt.Add(-time.Second)
						source.ReceivedAt = &at
					case "revoked":
						source.Status = "revoked"
					case "snapshot":
						copy := *source.Snapshot
						copy.GenerationID = "sample_" + strings.Repeat("b", 32)
						source.Snapshot = &copy
					case "future":
						future := source.Snapshot.CollectedAt.Add(time.Minute)
						copy := *source.Snapshot
						copy.CollectedAt = future
						source.Snapshot = &copy
					}
				}
				return source, nil
			}
			if kind == "catalog" {
				s.reviewComparator = reviewCompareFunc(func(c context.Context, a, b string) (int, error) {
					v := s.catalogStore.View(time.Now())
					_, e := s.catalogStore.Clear(c, v.Revision, time.Now())
					return -1, e
				})
			}
			w, _ := reviewResponse(t, s)
			if w.Code != 409 || strings.Contains(w.Body.String(), "fixture-binary") {
				t.Fatalf("changed input leaked %d", w.Code)
			}
		})
	}
}
func TestConditionalReviewFixedErrorsAndOperatorRecheck(t *testing.T) {
	s, source := reviewEnabled(t)
	s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) {
		return enrollmentstore.PackageView{}, errors.New("private-storage-content")
	}
	w, _ := reviewResponse(t, s)
	if w.Code != 500 || strings.Contains(w.Body.String(), "private-storage-content") {
		t.Fatal("raw error leaked")
	}
	s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) { return source, nil }
	var active atomic.Bool
	active.Store(true)
	s.reviewComparator = reviewCompareFunc(func(context.Context, string, string) (int, error) { active.Store(false); return -1, nil })
	r := httptest.NewRequest("GET", "/api/devices/demo-linux-01/security/review", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	out := httptest.NewRecorder()
	s.securityReview(out, r)
	if out.Code != 401 || strings.Contains(out.Body.String(), "fixture-binary") {
		t.Fatal("logged-out review result")
	}
}

func TestConditionalReviewAdmissionDeadlineAndFinishingAge(t *testing.T) {
	s, source := reviewEnabled(t)
	reads := 0
	s.lanPackages = func(ctx context.Context, _ string, _ time.Time) (enrollmentstore.PackageView, error) {
		reads++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 4*time.Second || time.Until(deadline) <= 0 {
			t.Fatal("missing bounded review context")
		}
		return source, nil
	}
	s.catalogReviews <- struct{}{}
	w, _ := reviewResponse(t, s)
	<-s.catalogReviews
	if w.Code != 429 || reads != 0 {
		t.Fatal("busy request reached provider")
	}
	w, _ = reviewResponse(t, s)
	if w.Code != 200 || reads != 2 {
		t.Fatal("bounded initial/current reads not performed")
	}
	current := source.ServerNow
	s.catalogNow = func() time.Time { return current }
	s.reviewComparator = reviewCompareFunc(func(context.Context, string, string) (int, error) {
		current = current.Add(3 * time.Minute)
		return -1, nil
	})
	w, _ = reviewResponse(t, s)
	if w.Code != 409 || strings.Contains(w.Body.String(), "fixture-binary") {
		t.Fatal("expired source returned review")
	}
}
func TestConditionalReviewCurrentReadFailureDiscardsResult(t *testing.T) {
	for _, failure := range []error{enrollmentstore.ErrBusy, errors.New("private-current-read-error")} {
		t.Run(failure.Error(), func(t *testing.T) {
			s, source := reviewEnabled(t)
			reads := 0
			s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) {
				reads++
				if reads > 1 {
					return enrollmentstore.PackageView{}, failure
				}
				return source, nil
			}
			w, _ := reviewResponse(t, s)
			want := 500
			if failure == enrollmentstore.ErrBusy {
				want = 429
			}
			if w.Code != want || strings.Contains(w.Body.String(), "fixture-binary") || strings.Contains(w.Body.String(), "private-current-read-error") {
				t.Fatal("uncertain current state leaked review")
			}
		})
	}
}
