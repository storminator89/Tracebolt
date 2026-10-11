package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsupdates"
	"strings"
	"time"
)

type patchContextCollector func(context.Context, windowspatchcontext.Request) (windowspatchcontext.Snapshot, error)

func validPatchContextConsent(c windowspatchcontext.Consent, binding string) bool {
	_, e := windowspatchcontext.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func samePatchContextConsent(read func() (windowspatchcontext.Consent, bool), c windowspatchcontext.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validPatchContextConsent(v, binding)
}
func appendWindowsPatchContext(ctx context.Context, m Material, f frame, c windowspatchcontext.Consent, collect patchContextCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validPatchContextConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, windowspatchcontext.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowspatchcontext.ValidateBinding(s, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsPatchContextVersion
	f.WindowsPatchContext = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append([]string{}, f.Observation.Privacy...)
	for i, text := range f.Observation.Privacy {
		f.Observation.Privacy[i] = strings.ReplaceAll(text, ", remote actions or updates are included.", ", remote actions or update installation are included.")
	}
	f.Observation.Privacy = append(f.Observation.Privacy, windowspatchcontext.Privacy)
	b, e := json.Marshal(f)
	if e != nil {
		return frame{}, nil, ErrObservation
	}
	if len(b) > MaxFrameBytes {
		section, _ := json.Marshal(s)
		minimal := s
		minimal.History.Rows = []windowspatchcontext.Entry{}
		minimal.History.Truncated = minimal.History.TotalCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		for remaining < len(minimum) {
			if !trimWindowsUpdateSibling(ctx, &f) {
				switch {
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
			if e != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, e = windowspatchcontext.FitBudget(s, remaining)
		if e != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsPatchContext = &s
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
func validateWindowsPatchContextFrame(f frame, fields map[string]json.RawMessage) error {
	if (f.SchemaVersion == FrameWindowsSecurityPostureVersion || (f.SchemaVersion == FrameWindowsSessionContextVersion || (f.SchemaVersion == FrameWindowsHardwareContextVersion || (f.SchemaVersion == FrameWindowsStorageContextVersion || (f.SchemaVersion == FrameWindowsSecurityCoverageVersion || (f.SchemaVersion == FrameWindowsResourceContextVersion || f.SchemaVersion == FrameWindowsStorageIOVersion)))))) && f.WindowsPatchContext == nil && len(fields["windowsPatchContext"]) == 0 {
		return nil
	}
	if f.SchemaVersion != FrameWindowsPatchContextVersion && f.SchemaVersion != FrameWindowsSecurityPostureVersion && f.SchemaVersion != FrameWindowsSessionContextVersion && f.SchemaVersion != FrameWindowsHardwareContextVersion && f.SchemaVersion != FrameWindowsStorageContextVersion && f.SchemaVersion != FrameWindowsSecurityCoverageVersion && f.SchemaVersion != FrameWindowsResourceContextVersion && f.SchemaVersion != FrameWindowsStorageIOVersion {
		if f.WindowsPatchContext != nil || len(fields["windowsPatchContext"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsPatchContext == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowspatchcontext.Decode(fields["windowsPatchContext"])
	if e != nil || windowspatchcontext.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID || f.WindowsAdapterContext != nil && s.GrantID == f.WindowsAdapterContext.GrantID {
		return ErrState
	}
	return nil
}
