package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowsupdates"
	"time"
)

type securityPostureCollector func(context.Context, windowssecurity.Request) (windowssecurity.Snapshot, error)

func validSecurityPostureConsent(c windowssecurity.Consent, binding string) bool {
	_, e := windowssecurity.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameSecurityPostureConsent(read func() (windowssecurity.Consent, bool), c windowssecurity.Consent, binding string) bool {
	if read == nil {
		return false
	}
	v, ok := read()
	return ok && v == c && validSecurityPostureConsent(v, binding)
}
func appendWindowsSecurityPosture(ctx context.Context, m Material, f frame, c windowssecurity.Consent, collect securityPostureCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validSecurityPostureConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if e := ctx.Err(); e != nil {
		return frame{}, nil, e
	}
	s, e := collect(ctx, windowssecurity.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if e != nil || windowssecurity.ValidateBinding(s, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsSecurityPostureVersion
	f.WindowsSecurityPosture = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append(append([]string{}, f.Observation.Privacy...), windowssecurity.Privacy)
	b, e := json.Marshal(f)
	for e == nil && len(b) > MaxFrameBytes {
		if !trimWindowsUpdateSibling(ctx, &f) {
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
func validateWindowsSecurityPostureFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsSecurityPostureVersion && !((f.SchemaVersion == FrameWindowsSessionContextVersion || f.SchemaVersion == FrameWindowsHardwareContextVersion) && len(fields["windowsSecurityPosture"]) != 0) {
		if f.WindowsSecurityPosture != nil || len(fields["windowsSecurityPosture"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsSecurityPosture == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowssecurity.Decode(fields["windowsSecurityPosture"])
	if e != nil || windowssecurity.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	if f.WindowsEvents != nil && s.GrantID == f.WindowsEvents.GrantID || f.WindowsVolumes != nil && s.GrantID == f.WindowsVolumes.GrantID || f.WindowsProcessMetrics != nil && s.GrantID == f.WindowsProcessMetrics.GrantID || f.WindowsNetwork != nil && s.GrantID == f.WindowsNetwork.GrantID || f.WindowsServiceStartup != nil && s.GrantID == f.WindowsServiceStartup.GrantID || f.WindowsUpdates != nil && s.GrantID == f.WindowsUpdates.GrantID || f.WindowsAdapterContext != nil && s.GrantID == f.WindowsAdapterContext.GrantID || f.WindowsPatchContext != nil && s.GrantID == f.WindowsPatchContext.GrantID {
		return ErrState
	}
	return nil
}
