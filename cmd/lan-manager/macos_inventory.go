package main

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/model"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Each domain retains an independent identity and immutable profile. Duplicate
// public device IDs are ambiguous and fail closed rather than joining records.
func mergedMacOSInventoryDevices(ctx context.Context, primary, windows, basic, inventory *enrollmentservice.Service, now time.Time) ([]model.Device, error) {
	if primary == nil || inventory == nil || inventory == primary || inventory == windows || inventory == basic || inventory.Platform() != "darwin" || inventory.Binding().Profile != "tls" || inventory.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory {
		return nil, errors.New("separate macOS inventory source unavailable")
	}
	var out []model.Device
	var err error
	if basic != nil {
		out, err = mergedMacOSDevices(ctx, primary, windows, basic, now)
	} else if windows != nil {
		out, err = mergedWindowsDevices(ctx, primary, windows, now)
	} else {
		out, err = primary.Devices(ctx, now)
	}
	if err != nil {
		return nil, err
	}
	rows, err := inventory.Devices(ctx, now)
	if err != nil {
		return nil, err
	}
	domains := 1
	if windows != nil {
		domains++
	}
	if basic != nil {
		domains++
	}
	return mergeMacOSInventoryRows(out, rows, domains)
}

func mergeMacOSInventoryRows(out, rows []model.Device, domains int) ([]model.Device, error) {
	if domains < 1 || domains > 3 || len(rows) > enrollmentservice.MaxRecords || len(out) > domains*enrollmentservice.MaxRecords {
		return nil, errors.New("device source exceeds bound")
	}
	for _, d := range rows {
		if d.Platform != "macos" {
			return nil, errors.New("macOS inventory device platform mismatch")
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

// Reserve the entire inventory family even when disabled. Unknown paths cannot
// fall through to basic macOS, Linux or Windows collection/action authorities.
func withMacOSInventoryIngress(primary, inventory http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && (r.URL.Path == "/v1/macos/inventory" || strings.HasPrefix(r.URL.Path, "/v1/macos/inventory/")) {
			if inventory == nil || r.URL.Path != "/v1/macos/inventory/control" && r.URL.Path != "/v1/macos/inventory/report" {
				http.NotFound(w, r)
				return
			}
			inventory.ServeHTTP(w, r)
			return
		}
		primary.ServeHTTP(w, r)
	})
}
