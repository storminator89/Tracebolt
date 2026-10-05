package api

import (
	"bytes"
	"context"
	"localrmm/internal/overviewledger"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompleteUpdatesFinalOutputRechecksAfterEncodingAndSession(t *testing.T) {
	for _, crossing := range []string{"encoding_expiry", "session_expiry", "session_revoked", "success"} {
		t.Run(crossing, func(t *testing.T) {
			start := time.Now().UTC()
			expiry := start.Add(time.Minute)
			var clock atomic.Int64
			clock.Store(start.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			h := operatorHandler{app: setup(t), enrollment: overviewServiceFixtureWithClock(t, "https://overview.invalid", now)}
			var active atomic.Bool
			active.Store(true)
			var encodes atomic.Int64
			r := httptest.NewRequest("POST", "/api/devices/fixture/inventory/complete-updates/query", nil)
			r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: func() bool {
				if crossing == "session_expiry" {
					clock.Store(expiry.UnixNano())
				}
				return active.Load()
			}}))
			value := overviewEncodingBoundaryFixture{calls: &encodes, payload: "private-synthetic-row-must-not-escape", afterEncode: func() {
				if crossing == "encoding_expiry" {
					clock.Store(expiry.UnixNano())
				}
				if crossing == "session_revoked" {
					active.Store(false)
				}
			}}
			checked := false
			check := func(at time.Time) error {
				checked = true
				if at.Before(expiry) {
					return nil
				}
				return overviewledger.ErrCursorExpired
			}
			w := httptest.NewRecorder()
			h.writeCompleteUpdatesResponse(w, r, value, 256<<10, check)
			if encodes.Load() != 1 {
				t.Fatal("checked page was encoded again before output")
			}
			if crossing == "success" {
				if w.Code != 200 || !checked || !bytes.Contains(w.Body.Bytes(), []byte(value.payload)) {
					t.Fatal("valid single-encoded page missing")
				}
				return
			}
			expected := 409
			if crossing == "session_revoked" {
				expected = 401
			}
			if w.Code != expected || bytes.Contains(w.Body.Bytes(), []byte(value.payload)) {
				t.Fatal("expired/revoked encoded page escaped", w.Code, w.Body.String())
			}
			if crossing != "session_revoked" && !checked {
				t.Fatal("final trusted clock was not checked")
			}
		})
	}
}
