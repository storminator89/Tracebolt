package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowseventhealth"
	"time"
)

type eventCollector func(context.Context, string, windowseventhealth.Consent, string) (windowseventhealth.Snapshot, error)

func validEventConsent(c windowseventhealth.Consent, binding string) bool {
	_, e := windowseventhealth.EncodeConsent(c, binding)
	return e == nil && c.Enabled
}
func sameEventConsent(read func() (windowseventhealth.Consent, bool), c windowseventhealth.Consent, binding string) bool {
	if read == nil {
		return false
	}
	now, ok := read()
	return ok && now == c && validEventConsent(now, binding)
}
func appendWindowsEvents(ctx context.Context, m Material, f frame, c windowseventhealth.Consent, collect eventCollector) (frame, []byte, error) {
	if !m.config.windowsInventory() || f.WindowsInventory == nil || !validEventConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	s, e := collect(ctx, f.WindowsInventory.GenerationID, c, m.binding)
	if e != nil || windowseventhealth.Validate(s) != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.GrantID != c.GrantID {
		return frame{}, nil, ErrObservation
	}
	// The event read follows the ordinary report. Only the envelope generation
	// time advances; every original metric, inventory and event capture is retained.
	f.Observation.GeneratedAt = time.Now().UTC()
	f.SchemaVersion = FrameWindowsEventsVersion
	f.WindowsEvents = &s
	f.Observation.Privacy = append(f.Observation.Privacy, windowseventhealth.Privacy)
	b, e := json.Marshal(f)
	if e != nil || len(b) > MaxFrameBytes || stale(f, time.Now().UTC()) {
		return frame{}, nil, ErrObservation
	}
	if _, e = decodeFrameForConfig(b, f.Sequence, m.config); e != nil {
		return frame{}, nil, e
	}
	return f, b, nil
}
func validateWindowsEventsFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion == FrameWindowsInventoryVersion {
		if f.WindowsEvents != nil || len(fields["windowsEvents"]) != 0 {
			return ErrState
		}
		return nil
	}
	if (f.SchemaVersion == FrameWindowsCapabilitiesVersion || f.SchemaVersion == FrameWindowsProcessMetricsVersion || f.SchemaVersion == FrameWindowsNetworkVersion || f.SchemaVersion == FrameWindowsServiceStartupVersion) && f.WindowsEvents == nil && len(fields["windowsEvents"]) == 0 {
		return nil
	}
	if (f.SchemaVersion != FrameWindowsEventsVersion && f.SchemaVersion != FrameWindowsCapabilitiesVersion && f.SchemaVersion != FrameWindowsProcessMetricsVersion && f.SchemaVersion != FrameWindowsNetworkVersion && f.SchemaVersion != FrameWindowsServiceStartupVersion) || f.WindowsEvents == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, e := windowseventhealth.Decode(fields["windowsEvents"])
	if e != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	return nil
}
