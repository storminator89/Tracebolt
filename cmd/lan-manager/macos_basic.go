package main

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/model"
	"net/http"
	"sort"
	"strings"
	"time"
)

func mergedMacOSDevices(ctx context.Context, primary, windows, macos *enrollmentservice.Service, now time.Time) ([]model.Device, error) {
	if primary == nil || macos == nil || macos == primary || macos == windows || macos.Platform() != "darwin" {
		return nil, errors.New("separate macOS source unavailable")
	}
	var out []model.Device
	var err error
	if windows != nil {
		out, err = mergedWindowsDevices(ctx, primary, windows, now)
	} else {
		out, err = primary.Devices(ctx, now)
	}
	if err != nil {
		return nil, err
	}
	rows, err := macos.Devices(ctx, now)
	if err != nil {
		return nil, err
	}
	if len(rows) > enrollmentservice.MaxRecords || windows == nil && len(out) > enrollmentservice.MaxRecords {
		return nil, errors.New("device source exceeds bound")
	}
	for _, d := range rows {
		if d.Platform != "macos" {
			return nil, errors.New("macOS device platform mismatch")
		}
	}
	out = append(out, rows...)
	seen := map[string]bool{}
	for _, d := range out {
		if seen[d.ID] {
			return nil, errors.New("ambiguous device identity")
		}
		seen[d.ID] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Reserve this exact family even when disabled; it must never fall through to
// Linux/Windows authority, auxiliary collectors or action handlers.
func withMacOSIngress(primary, macos http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, "/v1/macos/") {
			if r.URL.Path != "/v1/macos/telemetry" || macos == nil {
				http.NotFound(w, r)
				return
			}
			macos.ServeHTTP(w, r)
			return
		}
		primary.ServeHTTP(w, r)
	})
}
