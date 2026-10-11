package lanclient

import (
	"context"

	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsupdates"
	"time"
)

type securityCoverageCollector func(context.Context, windowssecuritycoverage.Request) (windowssecuritycoverage.Snapshot, error)

func validSecurityCoverageConsent(c windowssecuritycoverage.Consent, binding string) bool {
	_, e := windowssecuritycoverage.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameSecurityCoverageConsent(read func() (windowssecuritycoverage.Consent, bool), c windowssecuritycoverage.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validSecurityCoverageConsent(v, binding)
}
func appendWindowsSecurityCoverage(ctx context.Context, m Material, f frame, c windowssecuritycoverage.Consent, collect securityCoverageCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validSecurityCoverageConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, windowssecuritycoverage.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowssecuritycoverage.ValidateBinding(s, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsSecurityCoverageVersion
	f.WindowsSecurityCoverage = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append([]string{}, f.Observation.Privacy...)
	// v14 retains the historical 16-entry observation bound. Combining only the
	// final disclosure preserves all previous words and does not change old frames.
	if len(f.Observation.Privacy) >= 16 {
		f.Observation.Privacy[len(f.Observation.Privacy)-1] += " " + windowssecuritycoverage.TelemetryPrivacy
	} else {
		f.Observation.Privacy = append(f.Observation.Privacy, windowssecuritycoverage.TelemetryPrivacy)
	}
	b, e := json.Marshal(f)
	for e == nil && len(b) > MaxFrameBytes {
		if len(f.WindowsSecurityCoverage.Antivirus.Rows) > 0 {
			raw, _ := json.Marshal(f.WindowsSecurityCoverage)
			v, err := windowssecuritycoverage.FitBudget(*f.WindowsSecurityCoverage, len(raw)-1)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			f.WindowsSecurityCoverage = &v
		} else if f.WindowsStorageContext != nil && (len(f.WindowsStorageContext.Disks.Rows) > 0 || len(f.WindowsStorageContext.Drives.Rows) > 0) {
			raw, _ := json.Marshal(f.WindowsStorageContext)
			v, err := windowsstorage.FitBudget(*f.WindowsStorageContext, len(raw)-1)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			f.WindowsStorageContext = &v
		} else if f.WindowsSessionContext != nil && len(f.WindowsSessionContext.Sessions.Rows) > 0 {
			raw, _ := json.Marshal(f.WindowsSessionContext)
			v, err := windowssessions.FitBudget(*f.WindowsSessionContext, len(raw)-1)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			f.WindowsSessionContext = &v
		} else if !trimWindowsUpdateSibling(ctx, &f) {
			switch {
			case f.WindowsPatchContext != nil && len(f.WindowsPatchContext.History.Rows) > 0:
				raw, _ := json.Marshal(f.WindowsPatchContext)
				v, err := windowspatchcontext.FitBudget(*f.WindowsPatchContext, len(raw)-1)
				if err != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsPatchContext = &v
			case f.WindowsUpdates != nil && len(f.WindowsUpdates.Rows) > 0:
				raw, _ := json.Marshal(f.WindowsUpdates)
				v, err := windowsupdates.FitBudget(*f.WindowsUpdates, len(raw)-1)
				if err != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsUpdates = &v
			case f.WindowsAdapterContext != nil && len(f.WindowsAdapterContext.Rows) > 0:
				raw, _ := json.Marshal(f.WindowsAdapterContext)
				v, err := windowsadapters.FitBudget(*f.WindowsAdapterContext, len(raw)-1)
				if err != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsAdapterContext = &v
			default:
				return frame{}, nil, ErrObservation
			}
		}
		b, e = json.Marshal(f)
	}
	if e != nil || len(b) > MaxFrameBytes || stale(f, time.Now().UTC()) {
		return frame{}, nil, ErrObservation
	}
	if _, e = decodeFrameForConfig(b, f.Sequence, m.config); e != nil {

		return frame{}, nil, e
	}
	return f, b, nil
}
func validateWindowsSecurityCoverageFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsSecurityCoverageVersion {
		if f.WindowsSecurityCoverage != nil || len(fields["windowsSecurityCoverage"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsSecurityCoverage == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowssecuritycoverage.Decode(fields["windowsSecurityCoverage"])
	if e != nil || windowssecuritycoverage.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsStorageContext != nil && s.GrantID == f.WindowsStorageContext.GrantID || f.WindowsHardwareContext != nil && s.GrantID == f.WindowsHardwareContext.GrantID || f.WindowsSessionContext != nil && s.GrantID == f.WindowsSessionContext.GrantID || f.WindowsSecurityPosture != nil && s.GrantID == f.WindowsSecurityPosture.GrantID || f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID || f.WindowsAdapterContext != nil && s.GrantID == f.WindowsAdapterContext.GrantID || f.WindowsPatchContext != nil && s.GrantID == f.WindowsPatchContext.GrantID {
		return ErrState
	}
	return nil
}
