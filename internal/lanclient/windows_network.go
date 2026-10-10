package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"strings"
	"time"
)

type networkCollector func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error)

func validNetworkConsent(c windowsnetwork.Consent, binding string) bool {
	_, err := windowsnetwork.EncodeConsent(c, binding)
	return err == nil && c.Enabled
}
func sameNetworkConsent(read func() (windowsnetwork.Consent, bool), c windowsnetwork.Consent, binding string) bool {
	if read == nil {
		return false
	}
	current, ok := read()
	return ok && current == c && validNetworkConsent(current, binding)
}
func appendWindowsNetwork(ctx context.Context, m Material, f frame, c windowsnetwork.Consent, collect networkCollector) (frame, []byte, error) {
	if !m.config.windowsInventory() || f.WindowsInventory == nil || !validNetworkConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	s, err := collect(ctx, f.WindowsInventory.GenerationID, c.GrantID, time.Now().UTC())
	if err != nil || windowsnetwork.Validate(s) != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.GrantID != c.GrantID {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsNetworkVersion
	f.WindowsNetwork = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	for i, p := range f.Observation.Privacy {
		f.Observation.Privacy[i] = strings.ReplaceAll(p, ", sockets,", ", socket payloads,")
	}
	f.Observation.Privacy = append(f.Observation.Privacy, "Separately consented numeric TCP/UDP endpoint addresses, ports, TCP states and API-reported owning PIDs are included; no DNS, traffic content, stable process identity or AI export.")
	// Reserve the network envelope by dropping complete sibling rows only when
	// necessary. Preserve captures, counts and grant identities; retries never trim.
	b, err := json.Marshal(f)
	if err == nil && len(b) > MaxFrameBytes {
		section, e := json.Marshal(s)
		if e != nil {
			return frame{}, nil, ErrObservation
		}
		minimal := s
		minimal.Rows = []windowsnetwork.Endpoint{}
		minimal.Truncated = minimal.ObservedCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		for remaining < len(minimum) {
			// At most 64 volume and 128 process rows can be removed. FitBudget clones
			// each row slice; no caller-owned snapshot is mutated.
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
			} else {
				return frame{}, nil, ErrObservation
			}
			b, err = json.Marshal(f)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, err = windowsnetwork.FitBudget(s, remaining)
		if err != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsNetwork = &s
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
func validateWindowsNetworkFrame(f frame, fields map[string]json.RawMessage) error {
	if f.SchemaVersion == FrameWindowsServiceStartupVersion && f.WindowsNetwork == nil && len(fields["windowsNetwork"]) == 0 {
		return nil
	}
	if f.SchemaVersion != FrameWindowsNetworkVersion && f.SchemaVersion != FrameWindowsServiceStartupVersion {
		if f.WindowsNetwork != nil || len(fields["windowsNetwork"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsNetwork == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, err := windowsnetwork.Decode(fields["windowsNetwork"])
	if err != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.CollectedAt.After(f.Observation.GeneratedAt) || s.CollectedAt.Before(f.WindowsInventory.CollectedAt) {
		return ErrState
	}
	return nil
}
