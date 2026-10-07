package api

import (
	"bytes"
	"context"
	"localrmm/internal/enrollmentstate"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceHistoryOutputRechecksAfterEncoding(t *testing.T) {
	for _, crossing := range []string{"encoding_expiry", "session_check_expiry", "session_revoked", "success"} {
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
			r := httptest.NewRequest("GET", "/api/devices/fixture/resource-history", nil)
			r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: func() bool {
				if crossing == "session_check_expiry" {
					clock.Store(expiry.UnixNano())
				}
				return active.Load()
			}}))
			value := overviewEncodingBoundaryFixture{calls: &encodes, payload: "private-synthetic-resource-point", afterEncode: func() {
				if crossing == "encoding_expiry" {
					clock.Store(expiry.UnixNano())
				}
				if crossing == "session_revoked" {
					active.Store(false)
				}
			}}
			checked := false
			validate := func(at time.Time) error {
				checked = true
				if !at.Before(expiry) {
					return enrollmentstate.ErrExpired
				}
				return nil
			}
			w := httptest.NewRecorder()
			h.writeResourceHistoryResponse(w, r, value, validate)
			if encodes.Load() != 1 {
				t.Fatal("history encoded more than once")
			}
			if crossing == "success" {
				if w.Code != 200 || !checked || !bytes.Contains(w.Body.Bytes(), []byte(value.payload)) {
					t.Fatal("valid encoded history missing")
				}
				return
			}
			want := 409
			if crossing == "session_revoked" {
				want = 401
			}
			if w.Code != want || bytes.Contains(w.Body.Bytes(), []byte(value.payload)) {
				t.Fatal("expired encoded history escaped", w.Code)
			}
			if crossing != "session_revoked" && !checked {
				t.Fatal("trusted output clock not checked")
			}
		})
	}
}
