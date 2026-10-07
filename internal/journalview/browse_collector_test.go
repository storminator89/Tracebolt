package journalview

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

type browseFailureProvider struct {
	reader io.ReadCloser
	reason Reason
	err    error
}

func (p browseFailureProvider) Open(context.Context, Query) (io.ReadCloser, Reason, error) {
	return p.reader, p.reason, p.err
}

type browseCleanupReader struct {
	io.Reader
	close func() error
}

func (r browseCleanupReader) Close() error { return r.close() }
func TestRetainedEarlyCollectionFailuresKeepTheirVersionAndReason(t *testing.T) {
	q, now := browseFixture()
	for _, name := range []string{"permission", "factory", "canceled", "busy", "nil-reader", "nil-provider"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			slot := &atomic.Bool{}
			want := ReasonReadFailed
			factory := func() (Provider, error) { return browseFailureProvider{err: errors.New("synthetic read failure")}, nil }
			switch name {
			case "permission":
				want = ReasonPermissionDenied
				factory = func() (Provider, error) { return browseFailureProvider{err: SourceError{ReasonPermissionDenied}}, nil }
			case "factory":
				factory = func() (Provider, error) { return nil, errors.New("synthetic factory failure") }
			case "canceled":
				cancel()
				want = ReasonTimeout
			case "busy":
				slot.Store(true)
				want = ReasonCollectorBusy
			case "nil-reader":
				want = ReasonInvalidSource
				factory = func() (Provider, error) { return browseFailureProvider{reason: ReasonNone}, nil }
			case "nil-provider":
				want = ReasonInvalidSource
				factory = func() (Provider, error) { return nil, nil }
			}
			s, e := collectWith(ctx, q, now, slot, factory)
			if e != nil || s.SchemaVersion != SchemaVersionV2 || s.Coverage != Failed || s.Reason != want || s.Exhausted || s.NextCursor != "" {
				t.Fatal("early browse failure lost its typed reason")
			}
			if _, e := Encode(s); e != nil {
				t.Fatal("helper would reject typed failure", e)
			}
		})
	}
}
func TestRetainedCleanupFailuresClearExhaustionWithoutInventingContinuation(t *testing.T) {
	q, now := browseFixture()
	for _, kind := range []string{"close-error", "cancel-on-close", "close-error-empty", "cancel-on-close-empty"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ReasonReadFailed
			reader := browseCleanupReader{Reader: strings.NewReader(browseLine(q, 1, "synthetic readable message")), close: func() error { return errors.New("synthetic close failure") }}
			wantRows, wantCoverage := 1, Partial
			if strings.HasSuffix(kind, "-empty") {
				reader.Reader = strings.NewReader("")
				wantRows, wantCoverage = 0, Failed
			}
			if strings.HasPrefix(kind, "cancel-on-close") {
				want = ReasonTimeout
				reader.close = func() error { cancel(); return nil }
			}
			s, e := CollectWithProvider(ctx, q, now, browseFailureProvider{reader: reader, reason: ReasonNone})
			if e != nil || s.SchemaVersion != SchemaVersionV2 || s.Coverage != wantCoverage || s.Reason != want || s.Exhausted || s.NextCursor != "" || len(s.Rows) != wantRows {
				t.Fatal("cleanup failure retained successful exhaustion or lost projected rows")
			}
			if _, e := Encode(s); e != nil {
				t.Fatal("cleanup result is not encodable", e)
			}
		})
	}
}

func TestRetainedZeroRowProgressSurvivesCleanupFailures(t *testing.T) {
	for _, shape := range []string{"null-message-gap", "sparse-scan"} {
		for _, cleanup := range []string{"close-error", "cancel-on-close"} {
			t.Run(shape+"/"+cleanup, func(t *testing.T) {
				q, now := browseFixture()
				var input strings.Builder
				wantCursor := "s=fixture;i=1"
				if shape == "null-message-gap" {
					// Only the synthetic MESSAGE representation changes; its locator remains
					// validated and can anchor a subsequent bounded traversal.
					input.WriteString(strings.Replace(browseLine(q, 1, "null-projection-fixture"), `"MESSAGE":"null-projection-fixture"`, `"MESSAGE":null`, 1))
				} else {
					q.Search = "absent needle"
					for i := 0; i < MaxScannedRows+1; i++ {
						input.WriteString(browseLine(q, i, "haystack"))
					}
					wantCursor = "s=fixture;i=fff"
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				wantReason := ReasonReadFailed
				reader := browseCleanupReader{Reader: strings.NewReader(input.String()), close: func() error { return errors.New("synthetic cleanup failure") }}
				if cleanup == "cancel-on-close" {
					wantReason = ReasonTimeout
					reader.close = func() error { cancel(); return nil }
				}
				s, e := CollectWithProvider(ctx, q, now, browseFailureProvider{reader: reader, reason: ReasonNone})
				if e != nil || s.Coverage != Partial || s.Reason != wantReason || s.Exhausted || s.NextCursor != wantCursor || len(s.Rows) != 0 || s.ObservedCount != 0 || s.CountExact {
					t.Fatal("cleanup lost zero-row source progress")
				}
				digest, e := SnapshotDigest(s)
				if e != nil {
					t.Fatal("snapshot contract rejected valid continuation", e)
				}
				page, e := SelectPage(s, digest, 0, MaxPageRows)
				if e != nil || page.Coverage != Partial || page.NextCursor != wantCursor || page.Exhausted || len(page.Rows) != 0 {
					t.Fatal("page contract changed valid continuation", e)
				}
				if _, e := EncodePage(page); e != nil {
					t.Fatal("page continuation is not encodable", e)
				}
			})
		}
	}
}

func TestRetainedFailedCursorIsRejectedBySnapshotAndPageContracts(t *testing.T) {
	q, now := browseFixture()
	s := mark(empty(q, now), ReasonReadFailed)
	s.NextCursor = "s=fixture;i=1"
	if _, e := Encode(s); e == nil {
		t.Fatal("failed snapshot carried a contradictory continuation")
	}
	page := Page{SchemaVersion: SchemaVersionV2, Scope: Scope, SnapshotDigest: "sha256:" + strings.Repeat("a", 64), Query: q, ObservedAt: now, Coverage: Failed, Reason: ReasonReadFailed, Rows: []Row{}, CountExact: false, RedactionWarning: RedactionWarning, NextCursor: s.NextCursor}
	if _, e := EncodePage(page); e == nil {
		t.Fatal("failed page carried a contradictory continuation")
	}
}
