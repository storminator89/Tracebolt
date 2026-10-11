package lanclient

import (
	"context"

	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsupdates"
	"time"
)

// This v16-only reservation is applied before all dependent row bindings.
const windowsStorageIOBaseBytes = 26 * 1024

const windowsStorageIOTelemetryPrivacy = "Disk I/O: PerfDisk aggregate read/write throughput, operations, latency and queues with original sample window. Private; no per-device, health or AI inference."

type storageIOCollector func(context.Context, windowsstorageio.Request) (windowsstorageio.Snapshot, error)

func validStorageIOConsent(c windowsstorageio.Consent, binding string) bool {
	_, e := windowsstorageio.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameStorageIOConsent(read func() (windowsstorageio.Consent, bool), c windowsstorageio.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validStorageIOConsent(v, binding)
}
func appendWindowsStorageIO(ctx context.Context, m Material, f frame, c windowsstorageio.Consent, collect storageIOCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validStorageIOConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, windowsstorageio.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowsstorageio.ValidateBinding(s, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsStorageIOVersion
	f.WindowsStorageIO = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append([]string{}, f.Observation.Privacy...)
	// v16 retains the historical 16-entry observation bound. Combining only the
	// final disclosure preserves all previous words and does not change old frames.
	if len(f.Observation.Privacy) >= 16 {
		f.Observation.Privacy[len(f.Observation.Privacy)-1] += " " + windowsStorageIOTelemetryPrivacy
	} else {
		f.Observation.Privacy = append(f.Observation.Privacy, windowsStorageIOTelemetryPrivacy)
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
func validateWindowsStorageIOFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsStorageIOVersion {
		if f.WindowsStorageIO != nil || len(fields["windowsStorageIO"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsStorageIO == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowsstorageio.Decode(fields["windowsStorageIO"])
	if e != nil || windowsstorageio.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) || s.PerfDisk.SampleEndedAt != nil && s.PerfDisk.SampleEndedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsResourceContext != nil && s.GrantID == f.WindowsResourceContext.GrantID || f.WindowsSecurityCoverage != nil && s.GrantID == f.WindowsSecurityCoverage.GrantID || f.WindowsStorageContext != nil && s.GrantID == f.WindowsStorageContext.GrantID || f.WindowsHardwareContext != nil && s.GrantID == f.WindowsHardwareContext.GrantID || f.WindowsSessionContext != nil && s.GrantID == f.WindowsSessionContext.GrantID || f.WindowsSecurityPosture != nil && s.GrantID == f.WindowsSecurityPosture.GrantID || f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID || f.WindowsAdapterContext != nil && s.GrantID == f.WindowsAdapterContext.GrantID || f.WindowsPatchContext != nil && s.GrantID == f.WindowsPatchContext.GrantID {
		return ErrState
	}
	return nil
}
