package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"strings"
	"time"
)

type updatesCollector func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error)

func validUpdatesConsent(c windowsupdates.Consent, binding string) bool {
	_, err := windowsupdates.EncodeConsent(c, binding)
	return err == nil && c.Enabled
}
func sameUpdatesConsent(read func() (windowsupdates.Consent, bool), c windowsupdates.Consent, binding string) bool {
	if read == nil {
		return false
	}
	current, ok := read()
	return ok && current == c && validUpdatesConsent(current, binding)
}

// appendWindowsUpdates runs after every earlier extension. It never changes the
// final base rows or their order, keeping process/startup index bindings intact.
func appendWindowsUpdates(ctx context.Context, m Material, f frame, c windowsupdates.Consent, collect updatesCollector) (frame, []byte, error) {
	if ctx == nil || !m.config.windowsInventory() || f.WindowsInventory == nil || !validUpdatesConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return frame{}, nil, err
	}
	request := windowsupdates.Request{Consent: c, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt}
	s, err := collect(ctx, request)
	if ctx.Err() != nil {
		return frame{}, nil, ctx.Err()
	}
	if err != nil || windowsupdates.ValidateBinding(s, request.GenerationID, c.GrantID, request.CollectedAt) != nil {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion, f.WindowsUpdates = FrameWindowsUpdatesVersion, &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append([]string{}, f.Observation.Privacy...)
	for i, text := range f.Observation.Privacy {
		f.Observation.Privacy[i] = strings.ReplaceAll(text, ", remote actions or updates are included.", ", remote actions or update installation are included.")
	}
	f.Observation.Privacy = append(f.Observation.Privacy, windowsupdates.Privacy)
	b, err := json.Marshal(f)
	if err != nil {
		return frame{}, nil, ErrObservation
	}
	if len(b) > MaxFrameBytes {
		section, _ := json.Marshal(s)
		minimal := s
		minimal.Rows = []windowsupdates.Update{}
		minimal.Truncated = minimal.ObservedCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		for remaining < len(minimum) {
			if !trimWindowsUpdateSibling(ctx, &f) {
				return frame{}, nil, ErrObservation
			}
			b, err = json.Marshal(f)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, err = windowsupdates.FitBudget(s, remaining)
		if err != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsUpdates = &s
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

// Make room only by dropping complete optional sibling rows, without changing
// counts, original capture, grant, generation or the protected self metric.
func trimWindowsUpdateSibling(ctx context.Context, f *frame) bool {
	switch {
	case f.WindowsVolumes != nil && len(f.WindowsVolumes.Rows) > 0:
		raw, _ := json.Marshal(f.WindowsVolumes)
		s, e := windowsvolumes.FitBudget(*f.WindowsVolumes, len(raw)-1)
		if e != nil {
			return false
		}
		f.WindowsVolumes = &s
	case f.WindowsProcessMetrics != nil && canTrimProcessMetricRows(*f.WindowsProcessMetrics, processMetricSelfPID(ctx)):
		raw, _ := json.Marshal(f.WindowsProcessMetrics)
		s, e := windowsprocessmetrics.FitBudgetWithSelfPID(*f.WindowsProcessMetrics, len(raw)-1, processMetricSelfPID(ctx))
		if e != nil {
			return false
		}
		f.WindowsProcessMetrics = &s
	case f.WindowsNetwork != nil && len(f.WindowsNetwork.Rows) > 0:
		raw, _ := json.Marshal(f.WindowsNetwork)
		s, e := windowsnetwork.FitBudget(*f.WindowsNetwork, len(raw)-1)
		if e != nil {
			return false
		}
		f.WindowsNetwork = &s
	case f.WindowsServiceStartup != nil && len(f.WindowsServiceStartup.Rows) > 0:
		raw, _ := json.Marshal(f.WindowsServiceStartup)
		s, e := windowsmanaged.FitServiceStartupBudget(*f.WindowsServiceStartup, len(raw)-1)
		if e != nil {
			return false
		}
		f.WindowsServiceStartup = &s
	default:
		return false
	}
	return true
}

func validateWindowsUpdatesFrame(f frame, fields map[string]json.RawMessage) error {
	if (f.SchemaVersion == FrameWindowsAdapterContextVersion || (f.SchemaVersion == FrameWindowsPatchContextVersion || (f.SchemaVersion == FrameWindowsSecurityPostureVersion || (f.SchemaVersion == FrameWindowsSessionContextVersion || (f.SchemaVersion == FrameWindowsHardwareContextVersion || f.SchemaVersion == FrameWindowsStorageContextVersion))))) && f.WindowsUpdates == nil && len(fields["windowsUpdates"]) == 0 {
		return nil
	}
	if f.SchemaVersion != FrameWindowsUpdatesVersion && f.SchemaVersion != FrameWindowsAdapterContextVersion && f.SchemaVersion != FrameWindowsPatchContextVersion && f.SchemaVersion != FrameWindowsSecurityPostureVersion && f.SchemaVersion != FrameWindowsSessionContextVersion && f.SchemaVersion != FrameWindowsHardwareContextVersion && f.SchemaVersion != FrameWindowsStorageContextVersion {
		if f.WindowsUpdates != nil || len(fields["windowsUpdates"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsUpdates == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, err := windowsupdates.Decode(fields["windowsUpdates"])
	if err != nil || windowsupdates.ValidateBinding(s, f.WindowsInventory.GenerationID, s.GrantID, f.WindowsInventory.CollectedAt) != nil || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	grants := []string{}
	if f.WindowsEvents != nil {
		grants = append(grants, f.WindowsEvents.GrantID)
	}
	if f.WindowsVolumes != nil {
		grants = append(grants, f.WindowsVolumes.GrantID)
	}
	if f.WindowsProcessMetrics != nil {
		grants = append(grants, f.WindowsProcessMetrics.GrantID)
	}
	if f.WindowsNetwork != nil {
		grants = append(grants, f.WindowsNetwork.GrantID)
	}
	if f.WindowsServiceStartup != nil {
		grants = append(grants, f.WindowsServiceStartup.GrantID)
	}
	for _, grant := range grants {
		if grant == s.GrantID {
			return ErrState
		}
	}
	return nil
}
