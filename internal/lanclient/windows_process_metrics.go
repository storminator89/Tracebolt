package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"strings"
	"time"
)

type processMetricCollector func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error)

func nativeProcessMetricCollector(s *windowsprocessmetrics.Sampler) processMetricCollector {
	// Loaded material owns one bounded in-memory sampler across service cycles.
	// Fresh material/restart starts with explicit first-sample CPU; never a durable baseline.
	if s == nil {
		s = windowsprocessmetrics.NewSampler()
	}
	return s.Sample
}
func validProcessMetricConsent(c windowsprocessmetrics.Consent, binding string) bool {
	_, err := windowsprocessmetrics.EncodeConsent(c, binding)
	return err == nil && c.Enabled
}
func sameProcessMetricConsent(read func() (windowsprocessmetrics.Consent, bool), c windowsprocessmetrics.Consent, binding string) bool {
	if read == nil {
		return false
	}
	current, ok := read()
	return ok && current == c && validProcessMetricConsent(current, binding)
}
func appendWindowsProcessMetrics(ctx context.Context, m Material, f frame, c windowsprocessmetrics.Consent, collect processMetricCollector) (frame, []byte, error) {
	if !m.config.windowsInventory() || f.WindowsInventory == nil || !validProcessMetricConsent(c, m.binding) || collect == nil {
		return frame{}, nil, ErrConfiguration
	}
	pids := make([]uint32, 0, len(f.WindowsInventory.Processes.Rows))
	for _, p := range f.WindowsInventory.Processes.Rows {
		pids = append(pids, p.PID)
	}
	s, err := collect(ctx, pids, f.WindowsInventory.GenerationID, c.GrantID, f.WindowsInventory.CollectedAt)
	if err != nil || windowsprocessmetrics.Validate(s) != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.GrantID != c.GrantID {
		return frame{}, nil, ErrObservation
	}
	f.SchemaVersion = FrameWindowsProcessMetricsVersion
	f.WindowsProcessMetrics = &s
	f.Observation.GeneratedAt = time.Now().UTC()
	for i, p := range f.Observation.Privacy {
		f.Observation.Privacy[i] = strings.ReplaceAll(p, "owners, process memory, sockets", "owners, process memory contents, sockets")
	}
	f.Observation.Privacy = append(f.Observation.Privacy, "Separately consented per-process CPU and working-set byte counters are included; memory contents and AI export remain excluded.")
	b, err := json.Marshal(f)
	if err == nil && len(b) > MaxFrameBytes {
		section, e := json.Marshal(s)
		if e != nil {
			return frame{}, nil, ErrObservation
		}
		// A preceding volume extension may already use the entire frame budget.
		// Reserve the process header and disclosure by trimming complete volume rows,
		// then trim process rows to the remaining budget. Original counts/captures stay.
		minimal := s
		minimal.Rows = []windowsprocessmetrics.Process{}
		minimal.Truncated = minimal.ObservedCount > 0
		minimum, _ := json.Marshal(minimal)
		remaining := len(section) - (len(b) - MaxFrameBytes)
		if remaining < len(minimum) && f.WindowsVolumes != nil {
			volumeBytes, e := json.Marshal(f.WindowsVolumes)
			if e != nil {
				return frame{}, nil, ErrObservation
			}
			volumes, e := windowsvolumes.FitBudget(*f.WindowsVolumes, len(volumeBytes)-(len(minimum)-remaining))
			if e != nil {
				return frame{}, nil, ErrObservation
			}
			f.WindowsVolumes = &volumes
			b, err = json.Marshal(f)
			if err != nil {
				return frame{}, nil, ErrObservation
			}
			remaining = len(section) - (len(b) - MaxFrameBytes)
		}
		s, err = windowsprocessmetrics.FitBudget(s, remaining)
		if err != nil {
			return frame{}, nil, ErrObservation
		}
		f.WindowsProcessMetrics = &s
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
func validateWindowsProcessMetricsFrame(f frame, fields map[string]json.RawMessage) error {
	if (f.SchemaVersion == FrameWindowsNetworkVersion || f.SchemaVersion == FrameWindowsServiceStartupVersion) && f.WindowsProcessMetrics == nil && len(fields["windowsProcessMetrics"]) == 0 {
		return nil
	}
	if f.SchemaVersion != FrameWindowsProcessMetricsVersion && f.SchemaVersion != FrameWindowsNetworkVersion && f.SchemaVersion != FrameWindowsServiceStartupVersion {
		if f.WindowsProcessMetrics != nil || len(fields["windowsProcessMetrics"]) != 0 {
			return ErrState
		}
		return nil
	}
	if f.WindowsProcessMetrics == nil || f.WindowsInventory == nil {
		return ErrState
	}
	s, err := windowsprocessmetrics.Decode(fields["windowsProcessMetrics"])
	if err != nil || s.GenerationID != f.WindowsInventory.GenerationID || s.CollectedAt.After(f.Observation.GeneratedAt) || s.CollectedAt.Before(f.WindowsInventory.CollectedAt) {
		return ErrState
	}
	pids := map[uint32]bool{}
	for _, p := range f.WindowsInventory.Processes.Rows {
		pids[p.PID] = true
	}
	for _, p := range s.Rows {
		if !pids[p.PID] {
			return ErrState
		}
	}
	if int(s.ObservedCount) != len(pids) {
		return ErrState
	}
	return nil
}
