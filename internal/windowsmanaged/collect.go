package windowsmanaged

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"localrmm/internal/collector"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
)

// Collect must only be invoked after the caller has admitted the explicit
// windows-inventory-v1 local consent. It performs one native report collection;
// the shared-chart metrics and transport rows come from that same report.
func Collect(ctx context.Context, generationID string) (Snapshot, model.Device, error) {
	return collect(ctx, generationID, 0)
}

// CollectForProcessMetrics retains the already-enumerated local self PID for a
// separately consented process-metrics capture. It does not enumerate again or
// fabricate a missing row. Zero selects the ordinary inventory-only behavior.
// The caller must validate both inventory and process-metrics consent first.
func CollectForProcessMetrics(ctx context.Context, generationID string, selfPID uint32) (Snapshot, model.Device, error) {
	return collect(ctx, generationID, selfPID)
}

func collect(ctx context.Context, generationID string, selfPID uint32) (Snapshot, model.Device, error) {
	if ctx == nil || !validGeneration(generationID) {
		return Snapshot{}, model.Device{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	r, err := windowsinventory.Collect(ctx)
	if err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	return fromReport(r, generationID, selfPID)
}

// FromReport is a pure adapter for a native report or injected fixture. It does
// not consult the clock, collect sources, mutate the report, or replace capture
// times. Input rows are copied before deterministic sorting and transport trims.
func FromReport(r windowsinventory.Report, generationID string) (Snapshot, model.Device, error) {
	return fromReport(r, generationID, 0)
}

// FromReportForProcessMetrics is the pure adapter for an explicitly consented
// process-metrics capture. Only an existing self row is protected from row and
// byte trims. The original report, counts, capture and PID ordering are retained.
func FromReportForProcessMetrics(r windowsinventory.Report, generationID string, selfPID uint32) (Snapshot, model.Device, error) {
	return fromReport(r, generationID, selfPID)
}

func fromReport(r windowsinventory.Report, generationID string, selfPID uint32) (Snapshot, model.Device, error) {
	if !validGeneration(generationID) {
		return Snapshot{}, model.Device{}, ErrInvalidInput
	}
	if r.Schema != windowsinventory.Schema || r.Platform != "windows" || !validTime(r.CollectedAt) || !validText(r.OS, true, 512) || !validText(r.Uptime, true, 128) {
		return Snapshot{}, model.Device{}, ErrInvalidReport
	}
	if r.OSEvidence != nil && !collector.ValidWindowsOSEvidence(*r.OSEvidence, r.OS, r.CollectedAt) {
		return Snapshot{}, model.Device{}, ErrInvalidReport
	}
	for _, metric := range []model.Metric{r.CPU, r.Memory, r.Disk} {
		if !validMetric(metric) {
			return Snapshot{}, model.Device{}, ErrInvalidReport
		}
	}
	s := Snapshot{SchemaVersion: SchemaVersion, CollectionProfile: CollectionProfile, GenerationID: generationID, CollectedAt: r.CollectedAt}
	var err error
	if s.Hostname, err = adaptSection(r.Hostname, 1, validHostname); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if s.Processes, err = adaptSection(r.Processes, windowsinventory.MaxProcesses, validProcess); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if s.Services, err = adaptSection(r.Services, windowsinventory.MaxServices, validService); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if s.Software, err = adaptSection(r.Software, windowsinventory.MaxSoftware, validSoftware); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if s.Network, err = adaptSection(r.Network, windowsinventory.MaxAddresses, validAddress); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	sort.Slice(s.Processes.Rows, func(i, j int) bool {
		a, b := s.Processes.Rows[i], s.Processes.Rows[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.ParentPID != b.ParentPID {
			return a.ParentPID < b.ParentPID
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Threads < b.Threads
	})
	sort.Slice(s.Services.Rows, func(i, j int) bool {
		a, b := s.Services.Rows[i], s.Services.Rows[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		if a.State != b.State {
			return a.State < b.State
		}
		return a.PID < b.PID
	})
	sort.Slice(s.Software.Rows, func(i, j int) bool {
		a, b := s.Software.Rows[i], s.Software.Rows[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.RegistryView != b.RegistryView {
			return a.RegistryView < b.RegistryView
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Publisher < b.Publisher
	})
	sort.Slice(s.Network.Rows, func(i, j int) bool {
		a, b := s.Network.Rows[i], s.Network.Rows[j]
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.PrefixLength < b.PrefixLength
	})
	if err := trimProcesses(&s.Processes, MaxProcessRows, selfPID); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	trimRows(&s.Services, MaxServiceRows)
	trimRows(&s.Software, MaxSoftwareRows)
	trimRows(&s.Network, MaxNetworkRows)
	if err := fitBytesWithSelfPID(&s, selfPID); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	if err := Validate(s); err != nil {
		return Snapshot{}, model.Device{}, err
	}
	return s, deviceFromReport(r), nil
}

func adaptSection[T any](r windowsinventory.Section[T], maxObserved int, valid func(T) bool) (Section[T], error) {
	s := Section[T]{Source: r.Source, Scope: r.Scope, Quality: r.Quality, Complete: r.Complete, Truncated: r.Truncated, CountExact: r.Complete && !r.Truncated, Rows: []T{}}
	if len(r.Rows) > maxObserved {
		return Section[T]{}, ErrInvalidReport
	}
	s.ObservedCount = uint32(len(r.Rows))
	s.Rows = append(s.Rows, r.Rows...)
	switch r.Quality {
	case "healthy":
		s.Quality = QualityHealthy
	case "limited":
		s.Quality = QualityPartial
	case "unknown":
		s.Quality = QualityUnavailable
	case "denied":
		s.Quality = QualityDenied
	default:
		return Section[T]{}, ErrInvalidReport
	}
	if validateSection(s, maxObserved, maxObserved, valid) != nil {
		return Section[T]{}, ErrInvalidReport
	}
	return s, nil
}

func trimRows[T any](s *Section[T], limit int) {
	if len(s.Rows) <= limit {
		return
	}
	s.Rows = s.Rows[:limit:limit]
	s.Complete, s.Truncated, s.Quality = false, true, QualityPartial
}

// processDropIndex excludes only the local self PID selected by the consented
// caller. Rows have already been sorted; all other omissions remain highest-PID.
func processDropIndex(rows []Process, selfPID uint32) int {
	for i := len(rows) - 1; i >= 0; i-- {
		if selfPID == 0 || rows[i].PID != selfPID {
			return i
		}
	}
	return -1
}

func trimProcesses(s *Section[Process], limit int, selfPID uint32) error {
	for len(s.Rows) > limit {
		i := processDropIndex(s.Rows, selfPID)
		if i < 0 {
			return ErrSnapshotLimit
		}
		copy(s.Rows[i:], s.Rows[i+1:])
		trimRows(s, len(s.Rows)-1)
	}
	return nil
}

// fitBytesWithSelfPID removes the tail from the largest removable row section.
// Ties use the fixed section order. It cannot erase the hostname, counts,
// timestamps, provenance, or a native failure. Every step strictly removes a
// row; the record caps bound both encoding work and the number of iterations.
func fitBytesWithSelfPID(s *Snapshot, selfPID uint32) error {
	for {
		b, err := json.Marshal(s)
		if err != nil {
			return ErrInvalidSnapshot
		}
		if len(b) <= MaxSnapshotBytes {
			return nil
		}
		rows := []any{s.Processes.Rows, s.Services.Rows, s.Software.Rows, s.Network.Rows}
		counts := []int{len(s.Processes.Rows), len(s.Services.Rows), len(s.Software.Rows), len(s.Network.Rows)}
		largest, size := -1, 0
		for i, row := range rows {
			if counts[i] == 0 || i == 0 && processDropIndex(s.Processes.Rows, selfPID) < 0 {
				continue
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				return ErrInvalidSnapshot
			}
			if len(encoded) > size {
				largest, size = i, len(encoded)
			}
		}
		switch largest {
		case 0:
			if err := trimProcesses(&s.Processes, len(s.Processes.Rows)-1, selfPID); err != nil {
				return err
			}
		case 1:
			trimRows(&s.Services, len(s.Services.Rows)-1)
		case 2:
			trimRows(&s.Software, len(s.Software.Rows)-1)
		case 3:
			trimRows(&s.Network, len(s.Network.Rows)-1)
		default:
			return ErrSnapshotLimit
		}
	}
}

func validMetric(m model.Metric) bool {
	if m.Unit != "%" || !validText(m.Source, true, MaxMetadataBytes) || !validTime(m.CollectedAt) {
		return false
	}
	switch m.Quality {
	case "healthy", "stale":
		return m.Value != nil && !math.IsNaN(*m.Value) && !math.IsInf(*m.Value, 0) && *m.Value >= 0 && *m.Value <= 100
	case "unknown", "denied":
		return m.Value == nil
	}
	return false
}

func copyMetric(m model.Metric) model.Metric {
	if m.Value != nil {
		value := *m.Value
		m.Value = &value
	}
	return m
}

func deviceFromReport(r windowsinventory.Report) model.Device {
	d := model.Device{ID: "local-windows", Name: "Local Windows", Platform: "windows", OS: r.OS,
		Site: "Local machine", Group: "Local observations", Status: "unknown", Source: "local",
		LastSeen: r.CollectedAt, AgentVersion: "0.1.0-windows-inventory-preview", Uptime: r.Uptime,
		CPU: copyMetric(r.CPU), Memory: copyMetric(r.Memory), Disk: copyMetric(r.Disk),
		Tags: []string{"read-only", "local-only", "native-unverified"}, Capabilities: []model.Capability{},
		Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	if r.OSEvidence != nil {
		// FromReport validated this fixed source; preserve the original capture
		// and failure quality, with no timestamp refresh or caller-owned alias.
		d.Evidence = append(d.Evidence, *r.OSEvidence)
	}
	for _, row := range []struct {
		id, title, detail string
		metric            model.Metric
	}{
		{"cpu", "CPU utilization", "Two interval samples from one processor group; no process CPU attribution.", d.CPU},
		{"memory", "Physical memory utilization", "Physical memory not immediately available; no process or page-file memory.", d.Memory},
		{"disk", "System-volume utilization", "Caller-visible quota-aware system-volume capacity; not all disks or volumes.", d.Disk},
	} {
		if row.metric.CollectedAt.After(d.LastSeen) {
			d.LastSeen = row.metric.CollectedAt
		}
		value, status := "Unavailable", "limited"
		if row.metric.Value != nil {
			value = fmt.Sprintf("%.1f%%", *row.metric.Value)
		}
		if row.metric.Quality == "healthy" {
			status = "supported"
		}
		if row.metric.Quality == "denied" {
			status = "denied"
		}
		d.Capabilities = append(d.Capabilities, model.Capability{ID: row.id, Name: row.title, Status: status, Detail: row.detail})
		d.Evidence = append(d.Evidence, model.Evidence{ID: "local-windows-" + row.id, Title: row.title, Source: row.metric.Source, Quality: row.metric.Quality, CollectedAt: row.metric.CollectedAt, Detail: row.detail + " A valid sample does not establish device health or native acceptance.", Value: value})
	}
	d.Capabilities = append(d.Capabilities,
		model.Capability{ID: "native_verification", Name: "Native OS acceptance", Status: "limited", Detail: "Windows inventory source candidate. Installed-service, enrollment and native target acceptance remain unverified."},
		model.Capability{ID: "logs", Name: "Event content", Status: "unsupported", Detail: "Event content is outside this profile."},
		model.Capability{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "Service actions and updates are outside this profile."})
	return d
}
