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

func mergedWindowsDevices(ctx context.Context, primary, windows *enrollmentservice.Service, now time.Time) ([]model.Device, error) {
	if primary == nil || windows == nil || primary == windows {
		return nil, errors.New("separate Windows source unavailable")
	}
	a, err := primary.Devices(ctx, now)
	if err != nil {
		return nil, err
	}
	b, err := windows.Devices(ctx, now)
	if err != nil {
		return nil, err
	}
	if len(a) > enrollmentservice.MaxRecords || len(b) > enrollmentservice.MaxRecords {
		return nil, errors.New("device source exceeds bound")
	}
	out := append(a, b...)
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
func withWindowsIngress(primary, windows http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, "/v1/windows/") {
			if r.URL.Path != "/v1/windows/agent/telemetry" || windows == nil {
				http.NotFound(w, r)
				return
			}
			windows.ServeHTTP(w, r)
			return
		}
		primary.ServeHTTP(w, r)
	})
}
