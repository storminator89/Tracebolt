package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsupdates"
	"time"
)

type adapterContextCollector func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error)

func validAdapterContextConsent(c windowsadapters.Consent, binding string) bool {
	_, e := windowsadapters.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameAdapterContextConsent(read func() (windowsadapters.Consent, bool), c windowsadapters.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validAdapterContextConsent(v, binding)
}

// Appended last. Base capture start gives a conservative original age for this
// non-atomic reporting window and carries the floor through scope-absent frames.
func appendWindowsAdapterContext(ctx context.Context, m Material, f frame, c windowsadapters.Consent, collect adapterContextCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validAdapterContextConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt)
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowsadapters.Validate(s) != nil || s.GrantID != c.GrantID || s.GenerationID != f.WindowsInventory.GenerationID || !s.CollectedAt.Equal(f.WindowsInventory.CollectedAt) {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsAdapterContextVersion
	f.WindowsAdapterContext = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append(append([]string{}, f.Observation.Privacy...), windowsadapters.Privacy)
	b, e := json.Marshal(f)
	if e != nil {
		return frame{}, nil, ErrObservation
	}
	if len(b) > MaxFrameBytes {
		section, _ := json.Marshal(s)
		minimal := s
		minimal.Rows = []windowsadapters.Adapter{}
		minimal.Truncated = minimal.ObservedCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		for remaining < len(minimum) {
			if !trimWindowsUpdateSibling(ctx, &f) {
				if f.WindowsUpdates == nil || len(f.WindowsUpdates.Rows) == 0 {
					return frame{}, nil, ErrObservation
				}
				raw, _ := json.Marshal(f.WindowsUpdates)
				v, err := windowsupdates.FitBudget(*f.WindowsUpdates, len(raw)-1)
				if err != nil {
					return frame{}, nil, ErrObservation
				}
				f.WindowsUpdates = &v
			}
			b, e = json.Marshal(f)
			if e != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, e = windowsadapters.FitBudget(s, remaining)
		if e != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsAdapterContext = &s
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
func validateWindowsAdapterContextFrame(f frame, fields map[string]json.RawMessage) error {
	if (f.SchemaVersion == FrameWindowsPatchContextVersion || (f.SchemaVersion == FrameWindowsSecurityPostureVersion || f.SchemaVersion == FrameWindowsSessionContextVersion)) && f.WindowsAdapterContext == nil && len(fields["windowsAdapterContext"]) == 0 {
		return nil
	}
	if f.SchemaVersion != FrameWindowsAdapterContextVersion && f.SchemaVersion != FrameWindowsPatchContextVersion && f.SchemaVersion != FrameWindowsSecurityPostureVersion && f.SchemaVersion != FrameWindowsSessionContextVersion {
		if f.WindowsAdapterContext != nil || len(fields["windowsAdapterContext"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsAdapterContext == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowsadapters.Decode(fields["windowsAdapterContext"])
	if e != nil || s.GenerationID != f.WindowsInventory.GenerationID || !s.CollectedAt.Equal(f.WindowsInventory.CollectedAt) || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID {
		return ErrState
	}
	return nil
}
