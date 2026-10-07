package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsvolumes"
	"time"
)

type volumeCollector func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error)

func validVolumeConsent(c windowsvolumes.Consent, binding string) bool {
	_, err := windowsvolumes.EncodeConsent(c, binding)
	return err == nil && c.Enabled
}
func sameVolumeConsent(read func() (windowsvolumes.Consent, bool), c windowsvolumes.Consent, binding string) bool {
	if read == nil {
		return false
	}
	current, ok := read()
	return ok && current == c && validVolumeConsent(current, binding)
}
func appendWindowsVolumes(ctx context.Context, m Material, f frame, c windowsvolumes.Consent, collect volumeCollector) (frame, []byte, error) {
	if !m.config.windowsInventory() || f.WindowsInventory == nil || !validVolumeConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	s, err := collect(ctx, f.WindowsInventory.GenerationID, c, m.binding)
	if err != nil || windowsvolumes.Validate(s) != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.GrantID != c.GrantID {
		return frame{}, nil, ErrObservation
	}
	// v3 carries the separately consented volume extension and optional event
	// extension together. Older v1 and events-only v2 remain byte-shape unchanged.
	f.SchemaVersion = FrameWindowsCapabilitiesVersion
	f.WindowsVolumes = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	f.Observation.Privacy = append(f.Observation.Privacy, windowsvolumes.Privacy)
	b, err := json.Marshal(f)
	if err == nil && len(b) > MaxFrameBytes {
		section, encodeErr := json.Marshal(s)
		if encodeErr != nil {
			return frame{}, nil, ErrObservation
		}
		s, err = windowsvolumes.FitBudget(s, len(section)-(len(b)-MaxFrameBytes))
		if err != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsVolumes = &s
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
func validateWindowsVolumesFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion != FrameWindowsCapabilitiesVersion {
		if f.WindowsVolumes != nil || len(fields["windowsVolumes"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsVolumes == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, err := windowsvolumes.Decode(fields["windowsVolumes"])
	if err != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.CollectedAt.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	return nil
}
