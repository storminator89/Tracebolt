package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Real temp-store reads behind the same bounded maintenance slot; no collector.
func TestSystemPageReadAdmissionPreservesOriginalBoundaries(t *testing.T) {
	for _, boundary := range []string{"none", "cursor", "certificate", "cancel"} {
		t.Run(boundary, func(t *testing.T) {
			_, s, _, snap, cert := systemLongFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 2, at)
			saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
			q := SystemPageRequest{Section: "sockets", GenerationID: snapshot.GenerationID, Limit: 1}
			first, err := s.SystemPage(context.Background(), snap.Approval.DeviceID, q, at)
			if err != nil || first.NextCursor == "" || first.CursorExpiresAt == nil {
				t.Fatal("fixture cursor", err)
			}
			q.Cursor = first.NextCursor
			clock := &overviewFixtureClock{}
			clock.set(at)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = WithSystemViewClock(ctx, clock.now)
			release, err := s.inventoryAdmission(ctx)
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				page SystemPageResult
				err  error
			}
			done := make(chan result, 1)
			go func() { v, e := s.SystemPage(ctx, snap.Approval.DeviceID, q, at); done <- result{v, e} }()
			waitSystemMetadataReader(t, s, ctx)
			if _, err := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(err, ErrInventoryBusy) {
				t.Fatal("second metadata reader admitted", err)
			}
			var want error
			switch boundary {
			case "cursor":
				clock.set(*first.CursorExpiresAt)
				want = ErrSystemCursorExpired
			case "certificate":
				clock.set(time.Unix(snap.Intent.NotAfter, 0))
				want = enrollmentstate.ErrExpired
			case "cancel":
				cancel()
				want = context.Canceled
			default:
				clock.set(at.Add(time.Second))
			}
			release()
			out := <-done
			if want != nil {
				if !errors.Is(out.err, want) || !reflect.DeepEqual(out.page, SystemPageResult{}) {
					t.Fatal("crossed authority exposed rows", out.err)
				}
			} else {
				if out.err != nil || out.page.GenerationID != snapshot.GenerationID || out.page.ReturnedCount != 1 || !out.page.Meta.ObservedAt.Equal(at) || !out.page.CheckedAt().Equal(at.Add(time.Second)) {
					t.Fatal("bounded wait changed original capture", out.err)
				}
				raw, _ := json.Marshal(out.page)
				if strings.Contains(string(raw), "boundary") || strings.Contains(string(raw), "checkedAt") {
					t.Fatal("private lifetime escaped wire")
				}
				if p, e := out.page.RecheckAt(*first.CursorExpiresAt); !errors.Is(e, ErrSystemCursorExpired) || !reflect.DeepEqual(p, SystemPageResult{}) {
					t.Fatal("final output renewed original cursor", e)
				}
				// Copying an earlier clock cannot extend the committed read boundary.
				again, e := out.page.RecheckAt(at)
				if e != nil || !again.CheckedAt().Equal(out.page.CheckedAt()) {
					t.Fatal("clock rollback lowered checked time", e)
				}
			}
			if len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
				t.Fatal("page leaked shared gate")
			}
		})
	}
}
