package linuxcve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/assessment"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"strings"
	"time"
)

// Evaluate performs one bounded step without retaining progress. Durable callers
// use EvaluateStep and commit the returned checkpoint before acknowledging it.
func Evaluate(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, comparator assessment.VersionComparator, now time.Time) Result {
	result, _, _ := EvaluateStep(ctx, snapshot, manifest, rows, comparator, now, AssessmentIdentity{}, nil)
	return result
}

func matchRule(r rule, installed string, compare func(string, string) (int, error)) (string, bool, error) {
	if r.fixed != "" {
		cmp, err := compare(installed, r.fixed)
		return r.fixed, err == nil && cmp < 0, err
	}
	for _, rg := range r.intervals {
		if rg.introduced != "0" {
			bounds, err := compare(rg.introduced, rg.fixed)
			if err != nil {
				return "", false, err
			}
			if bounds >= 0 {
				return "", false, assessment.ErrVersionInvalid
			}
			start, err := compare(installed, rg.introduced)
			if err != nil {
				return "", false, err
			}
			if start < 0 {
				continue
			}
		}
		end, err := compare(installed, rg.fixed)
		if err != nil {
			return "", false, err
		}
		if end < 0 {
			return rg.fixed, true, nil
		}
	}
	return "", false, nil
}

func excludedVersion(v string) bool {
	v = strings.ToLower(v)
	for _, marker := range []string{"~bpo", "+bpo", "ppa", "+local", "~local", ".local", "-local", "+custom", "~custom", "+rebuild", "~rebuild"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func validInventory(ctx context.Context, m fullinventory.Manifest, rows []linuxpackages.PackageRow) bool {
	if rows == nil || fullinventory.ValidateManifest(m) != nil || uint64(len(rows)) != m.ObservedCount {
		return false
	}
	h := sha256.New()
	// The complete-inventory v1 contract's canonical row digest domain.
	_, _ = h.Write([]byte("tracebolt.complete-linux-packages.rows.v1\x00"))
	var installed, canonicalBytes uint64
	for i, p := range rows {
		if ctx.Err() != nil || fullinventory.ValidateRow(p) != nil {
			return false
		}
		if i > 0 && (rows[i-1].Name > p.Name || rows[i-1].Name == p.Name && rows[i-1].Architecture >= p.Architecture) {
			return false
		}
		if p.InstallState == "installed" {
			installed++
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return false
		}
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{'\n'})
		canonicalBytes += uint64(len(raw) + 1)
	}
	return installed == m.InstalledCount && canonicalBytes == m.CanonicalRowBytes && hex.EncodeToString(h.Sum(nil)) == m.RowsSHA256
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
