package lanclient

import (
	"context"

	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsupdates"
	"time"
)

// This v15-only reservation is applied before all dependent row bindings.
const windowsResourceContextBaseBytes = 28 * 1024

const windowsResourceContextTelemetryPrivacy = "CPU/memory: source-labeled processor counts, installed and usable RAM, commit capacity and aggregate pagefiles. Private; no paging-I/O or health verdict and no AI export."

type resourceContextCollector func(context.Context, windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error)

func validResourceContextConsent(c windowsresourcecontext.Consent, binding string) bool {
	_, e := windowsresourcecontext.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameResourceContextConsent(read func() (windowsresourcecontext.Consent, bool), c windowsresourcecontext.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validResourceContextConsent(v, binding)
}
func appendWindowsResourceContext(ctx context.Context, m Material, f frame, c windowsresourcecontext.Consent, collect resourceContextCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validResourceContextConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, windowsresourcecontext.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowsresourcecontext.ValidateBinding(s, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsResourceContextVersion
	f.WindowsResourceContext = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append([]string{}, f.Observation.Privacy...)
	// v15 retains the historical 16-entry observation bound. Combining only the
	// final disclosure preserves all previous words and does not change old frames.
	if len(f.Observation.Privacy) >= 16 {
		f.Observation.Privacy[len(f.Observation.Privacy)-1] += " " + windowsResourceContextTelemetryPrivacy
	} else {
		f.Observation.Privacy = append(f.Observation.Privacy, windowsResourceContextTelemetryPrivacy)
	}
	b, e := json.Marshal(f)
	for e == nil && len(b) > MaxFrameBytes {
		if f.WindowsSecurityCoverage != nil && len(f.WindowsSecurityCoverage.Antivirus.Rows) > 0 {
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
func validateWindowsResourceContextFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsResourceContextVersion && f.SchemaVersion != FrameWindowsStorageIOVersion {
		if f.WindowsResourceContext != nil || len(fields["windowsResourceContext"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.SchemaVersion == FrameWindowsStorageIOVersion && f.WindowsResourceContext == nil && len(fields["windowsResourceContext"]) == 0 {
		return nil
	}
	if f.WindowsResourceContext == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowsresourcecontext.Decode(fields["windowsResourceContext"])
	if e != nil || windowsresourcecontext.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsSecurityCoverage != nil && s.GrantID == f.WindowsSecurityCoverage.GrantID || f.WindowsStorageContext != nil && s.GrantID == f.WindowsStorageContext.GrantID || f.WindowsHardwareContext != nil && s.GrantID == f.WindowsHardwareContext.GrantID || f.WindowsSessionContext != nil && s.GrantID == f.WindowsSessionContext.GrantID || f.WindowsSecurityPosture != nil && s.GrantID == f.WindowsSecurityPosture.GrantID || f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID || f.WindowsAdapterContext != nil && s.GrantID == f.WindowsAdapterContext.GrantID || f.WindowsPatchContext != nil && s.GrantID == f.WindowsPatchContext.GrantID {
		return ErrState
	}
	return nil
}
