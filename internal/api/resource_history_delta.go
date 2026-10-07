package api

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"net/url"
	"strconv"
	"strings"
)

// The cursor is a payload optimization only. It confers no access and never
// bypasses the full current authenticated, expiry-checked store read.
func resourceHistoryAfter(u *url.URL) (string, bool) {
	if u == nil || u.ForceQuery {
		return "", false
	}
	if u.RawQuery == "" {
		return "", true
	}
	const prefix = "afterSequence="
	if !strings.HasPrefix(u.RawQuery, prefix) {
		return "", false
	}
	value := strings.TrimPrefix(u.RawQuery, prefix)
	n, err := strconv.ParseUint(value, 10, 63)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
		return "", false
	}
	return value, true
}

type resourceHistoryDelta struct {
	enrollmentstore.ResourceHistoryView
	BaseSequence string `json:"baseSequence"`
	LastSequence string `json:"lastSequence"`
	PointCount   int    `json:"pointCount"`
}

// Full bootstrap and full terminal replies retain the existing v1 contract.
// Deltas contain every newer authentic minute point, including replacements in
// the latest minute. Server clock and the exact full point count let the reader
// expire and verify its session-local merge without downsampling or backfill.
func resourceHistoryPayload(view enrollmentstore.ResourceHistoryView, after string) (any, error) {
	if after == "" || view.Status != "available" || len(view.Points) == 0 {
		return view, nil
	}
	base, e := strconv.ParseUint(after, 10, 63)
	if e != nil || base == 0 || strconv.FormatUint(base, 10) != after {
		return nil, enrollmentstore.ErrStorage
	}
	last := view.Points[len(view.Points)-1].Sequence
	latest, e := strconv.ParseUint(last, 10, 63)
	if e != nil {
		return nil, enrollmentstore.ErrStorage
	}
	// A newer client watermark may follow an explicit state recovery. Send the
	// full verified view rather than claiming a delta from an unknown future.
	if base > latest {
		return view, nil
	}
	count := len(view.Points)
	points := make([]enrollmentstore.ResourcePoint, 0)
	for _, point := range view.Points {
		sequence, e := strconv.ParseUint(point.Sequence, 10, 63)
		if e != nil {
			return nil, enrollmentstore.ErrStorage
		}
		if sequence > base {
			points = append(points, point)
		}
	}
	view.SchemaVersion = "tracebolt.resource-history-delta.v1"
	view.Points = points
	return resourceHistoryDelta{ResourceHistoryView: view, BaseSequence: after, LastSequence: last, PointCount: count}, nil
}

// Keep the outer operator router's exception limited to this exact endpoint.
func resourceHistoryQueryAllowed(u *url.URL) bool {
	if u == nil {
		return false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "resource-history" {
		return false
	}
	_, ok := resourceHistoryAfter(u)
	return ok
}
