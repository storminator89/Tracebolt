package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"time"
)

type serviceStartupCollector func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error)

func validServiceStartupConsent(c windowsmanaged.ServiceStartupConsent, binding string) bool {
	_, err := windowsmanaged.EncodeServiceStartupConsent(c, binding)
	return err == nil && c.Enabled
}
func sameServiceStartupConsent(read func() (windowsmanaged.ServiceStartupConsent, bool), c windowsmanaged.ServiceStartupConsent, binding string) bool {
	if read == nil {
		return false
	}
	current, ok := read()
	return ok && current == c && validServiceStartupConsent(current, binding)
}

// appendWindowsServiceStartup runs last, after the final base inventory row trim.
// The digest binds exact service values and order, including duplicate/redacted
// display names. No base row is changed, reordered, or removed here.
func appendWindowsServiceStartup(ctx context.Context, m Material, f frame, c windowsmanaged.ServiceStartupConsent, collect serviceStartupCollector) (frame, []byte, error) {
	if !m.config.windowsInventory() || f.WindowsInventory == nil || !validServiceStartupConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	rows := append([]windowsmanaged.Service{}, f.WindowsInventory.Services.Rows...)
	digest, err := windowsmanaged.ServiceStartupRowsSHA256(rows)
	if err != nil {
		return frame{}, nil, ErrObservation
	}
	s, err := collect(ctx, rows, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt)
	if err != nil || windowsmanaged.ValidateServiceStartup(s) != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.GrantID != c.GrantID || s.ServicesSHA256 != digest || int(s.RequestedCount) != len(rows) {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion, f.WindowsServiceStartup = FrameWindowsServiceStartupVersion, &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append(f.Observation.Privacy, windowsmanaged.ServiceStartupPrivacy)
	// Reserve the minimal envelope by trimming only complete optional sibling
	// rows. Then trim highest-index startup rows deterministically. All original
	// captures/counts/grants remain unchanged and pending retries reuse exact bytes.
	b, err := json.Marshal(f)
	if err == nil && len(b) > MaxFrameBytes {
		section, e := json.Marshal(s)
		if e != nil {
			return frame{}, nil, ErrObservation
		}
		minimal := s
		minimal.Rows = []windowsmanaged.ServiceStartupRow{}
		minimal.Truncated = minimal.RequestedCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		for remaining < len(minimum) {
			if f.WindowsVolumes != nil && len(f.WindowsVolumes.Rows) > 0 {
				raw, _ := json.Marshal(f.WindowsVolumes)
				v, e := windowsvolumes.FitBudget(*f.WindowsVolumes, len(raw)-1)
				if e != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsVolumes = &v
			} else if f.WindowsProcessMetrics != nil && canTrimProcessMetricRows(*f.WindowsProcessMetrics, processMetricSelfPID(ctx)) {
				raw, _ := json.Marshal(f.WindowsProcessMetrics)
				v, e := windowsprocessmetrics.FitBudgetWithSelfPID(*f.WindowsProcessMetrics, len(raw)-1, processMetricSelfPID(ctx))
				if e != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsProcessMetrics = &v
			} else if f.WindowsNetwork != nil && len(f.WindowsNetwork.Rows) > 0 {
				raw, _ := json.Marshal(f.WindowsNetwork)
				v, e := windowsnetwork.FitBudget(*f.WindowsNetwork, len(raw)-1)
				if e != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsNetwork = &v
			} else {
				return frame{}, nil, ErrObservation
			}
			b, err = json.Marshal(f)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, err = windowsmanaged.FitServiceStartupBudget(s, remaining)
		if err != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsServiceStartup = &s
		b, err = json.Marshal(f)
	}
	if err != nil || len(b) > MaxFrameBytes || stale(f, time.Now().UTC()) {
		return frame{}, nil, ErrObservation
	}
	if _, err = decodeFrameForConfig(b, f.Sequence, m.config); err != nil {
		return frame{}, nil, err
	}
	return f, b, nil
}
func validateWindowsServiceStartupFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsServiceStartupVersion {
		if f.WindowsServiceStartup != nil || len(fields["windowsServiceStartup"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsServiceStartup == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, err := windowsmanaged.DecodeServiceStartup(fields["windowsServiceStartup"])
	digest, digestErr := windowsmanaged.ServiceStartupRowsSHA256(f.WindowsInventory.Services.Rows)
	if err != nil || digestErr != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.ServicesSHA256 != digest || int(s.RequestedCount) != len(f.WindowsInventory.Services.Rows) || s.CollectedAt.After(f.Observation.GeneratedAt) || s.CollectedAt.Before(f.WindowsInventory.CollectedAt) {
		return ErrState
	}
	return nil
}
