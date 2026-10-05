package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/packagecollector"
	"localrmm/internal/signedhttp"
	"net/http"
	"time"
)

type frame struct {
	SchemaVersion string                  `json:"schemaVersion"`
	Sequence      uint64                  `json:"sequence"`
	Observation   bundle.Bundle           `json:"observation"`
	Operational   *operational.Snapshot   `json:"operational,omitempty"`
	Packages      *linuxpackages.Snapshot `json:"packages,omitempty"`
}
type receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	AgentID       string    `json:"agentId"`
	Sequence      uint64    `json:"sequence"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	Duplicate     bool      `json:"duplicate"`
}
type Report struct {
	CachedUpdatesStatus         string `json:"cachedUpdatesStatus,omitempty"`
	CachedUpdatesSequence       uint64 `json:"cachedUpdatesSequence,omitempty"`
	CachedUpdatesOperations     uint8  `json:"cachedUpdatesOperations,omitempty"`
	ProcessesStatus             string `json:"processesStatus,omitempty"`
	ProcessesSequence           uint64 `json:"processesSequence,omitempty"`
	VolumesStatus               string `json:"volumesStatus,omitempty"`
	VolumesSequence             uint64 `json:"volumesSequence,omitempty"`
	OverviewOperations          uint8  `json:"overviewOperations,omitempty"`
	JournalStatus               string `json:"journalStatus,omitempty"`
	SchemaVersion               string `json:"schemaVersion"`
	Status                      string `json:"status"`
	Profile                     string `json:"profile"`
	Sequence                    uint64 `json:"sequence,omitempty"`
	Duplicate                   bool   `json:"duplicate"`
	RetriedPending              bool   `json:"retriedPending"`
	DiscardedStale              bool   `json:"discardedStale"`
	AvailablePercentageFields   int    `json:"availablePercentageFields"`
	UnavailablePercentageFields int    `json:"unavailablePercentageFields"`
	InventoryStatus             string `json:"inventoryStatus,omitempty"`
	InventorySequence           uint64 `json:"inventorySequence,omitempty"`
	InventoryOperations         uint8  `json:"inventoryOperations,omitempty"`
	SystemStatus                string `json:"systemStatus,omitempty"`
	SystemSequence              uint64 `json:"systemSequence,omitempty"`
	SystemRetriedPending        bool   `json:"systemRetriedPending,omitempty"`
	SystemDiscardedStale        bool   `json:"systemDiscardedStale,omitempty"`
}

// Run preserves the legacy one-shot collection/delivery behavior. The explicitly
// complete profile adds serialized system/package work with separate cooperative
// stage budgets. Separate full-update consent adds a 20s/64-operation burst;
// explicit overview consent adds one shared 20s/64-operation
// process-and-volume burst before the existing journal stage. The caller's own
// deadline still bounds the one-shot call; these stage budgets are not a hard
// overall cycle deadline. Pending bytes and original source times survive retry.
// This path never switches origin, enrolls or installs.
func Run(ctx context.Context, m Material) (Report, error) {
	report := Report{SchemaVersion: "tracebolt.agent-run.v1", Status: "failed", Profile: m.config.Profile}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !m.valid() {
		return report, ErrConfiguration
	}
	report.Profile = m.config.Profile
	state, e := openSenderState(m)
	if e != nil {
		return report, ErrState
	}
	defer state.Close()
	var inventory *inventorySender
	var system *systemSender
	if m.config.complete() {
		inventory, e = openInventorySender(m)
		if e != nil {
			return report, e
		}
		defer inventory.Close()
		system, e = openSystemSender(m)
		if e != nil {
			return report, e
		}
		defer system.Close()
	}
	if inventory == nil {
		// Preserve the preexisting one-shot caller-context contract. Legacy
		// foreground attempts retain their original20s budget separately.
		return runUsingState(ctx, m, state)
	}
	updates, e := openCompleteUpdatesSender(m)
	if e != nil {
		return report, e
	}
	defer updates.Close()
	overview, e := openOverviewSender(m)
	if e != nil {
		return report, e
	}
	defer overview.Close()
	journal := openJournalSender(m)
	defer journal.Close()
	report, err := runPreparedAttemptWithSystem(ctx, m, state, system, inventory, runUsingState)
	if err == nil {
		err = runCompleteUpdatesAttempt(ctx, updates, &report)
	}
	if err == nil {
		err = runOverviewAndJournal(ctx, overview, &report, func(parent context.Context) string { return runJournalAttempt(parent, journal) })
	}
	return report, err
}

// Complete-profile work is serialized: a bounded metric attempt followed by a
// bounded inventory burst. The caller retains both locks across this function.
// Normal chunk-budget exhaustion is pending progress, not exponential backoff.
func runPreparedAttempt(ctx context.Context, m Material, state *lanclientstate.State, inventory *inventorySender, metrics func(context.Context, Material, *lanclientstate.State) (Report, error)) (Report, error) {
	return runPreparedAttemptWithSystem(ctx, m, state, nil, inventory, metrics)
}
func runPreparedAttemptWithSystem(ctx context.Context, m Material, state *lanclientstate.State, system *systemSender, inventory *inventorySender, metrics func(context.Context, Material, *lanclientstate.State) (Report, error)) (Report, error) {
	metricCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	report, err := metrics(metricCtx, m, state)
	cancel()
	if err != nil {
		return report, err
	}
	if system != nil {
		systemCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		status, e := system.Run(systemCtx)
		cancel()
		report.SystemStatus, report.SystemSequence = status.Status, status.Sequence
		report.SystemRetriedPending, report.SystemDiscardedStale = status.RetriedPending, status.DiscardedStale
		if e != nil {
			return report, e
		}
	}
	if inventory == nil {
		return report, nil
	}
	burstCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	status, inventoryErr := inventory.Burst(burstCtx)
	cancel()
	report.InventoryStatus = status.Status
	report.InventorySequence = status.Sequence
	report.InventoryOperations = uint8(status.Operations)
	if errors.Is(inventoryErr, ErrInventoryPending) {
		inventoryErr = nil
	}
	return report, inventoryErr
}

// runUsingState preserves one exclusive ledger lock across foreground attempts.
func runUsingState(ctx context.Context, m Material, state *lanclientstate.State) (Report, error) {
	return runUsingStateWithCollectors(ctx, m, state, operational.Collect, packagecollector.Collect)
}

// The collector is a per-attempt dependency, never an asynchronous background job.
func runUsingStateWithCollector(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot) (Report, error) {
	return runUsingStateWithCollectors(ctx, m, state, collectOperations, packagecollector.Collect)
}

func runUsingStateWithCollectors(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (Report, error) {
	return runUsingStateWithSources(ctx, m, state, collectOperations, collectPackages, collector.Snapshot)
}

// All dependencies are private per-attempt values. Tests can exercise staging
// and transport without reading any production observation source.
func runUsingStateWithSources(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device) (Report, error) {
	report := Report{SchemaVersion: "tracebolt.agent-run.v1", Status: "failed", Profile: m.config.Profile}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !m.valid() {
		return report, ErrConfiguration
	}
	pending, e := state.Pending()
	if e != nil {
		return report, ErrState
	}
	var f frame
	var body []byte
	if pending != nil {
		f, e = decodeFrameForConfig(pending.Body(), pending.Sequence, m.config)
		if e != nil {
			return report, ErrState
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if stale(f, time.Now().UTC()) {
			if state.Discard(pending.Digest) != nil {
				return report, ErrState
			}
			pending = nil
			report.DiscardedStale = true
		} else {
			report.RetriedPending = true
		}
	}
	if pending == nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		sequence, e := state.NextSequence()
		if e != nil {
			return report, ErrState
		}
		if m.config.managed() && sequence > operational.MaxSafeInteger {
			return report, ErrState
		}
		f, body, e = collectFrameWithSources(ctx, m.config, sequence, collectOperations, collectPackages, collectBasic)
		if e != nil {
			return report, e
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		p, e := state.Stage(sequence, body)
		if e != nil {
			return report, ErrState
		}
		pending = &p
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	report.Sequence = pending.Sequence
	for _, v := range []bool{f.Observation.Observation.CPU.Value != nil && f.Observation.Observation.CPU.Quality == "healthy", f.Observation.Observation.Memory.Value != nil && f.Observation.Observation.Memory.Quality == "healthy", f.Observation.Observation.Disk.Value != nil && f.Observation.Observation.Disk.Quality == "healthy"} {
		if v {
			report.AvailablePercentageFields++
		} else {
			report.UnavailablePercentageFields++
		}
	}
	report.Status = "pending_retained"
	var req *http.Request
	if m.config.Profile == "http-test" {
		req, e = signedhttp.NewSignedRequest(ctx, m.config.ManagerOrigin, m.certificate, pending.Sequence, f.Observation.GeneratedAt, pending.Body())
	} else {
		req, e = http.NewRequestWithContext(ctx, "POST", m.config.ManagerOrigin+signedhttp.Path, bytes.NewReader(pending.Body()))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return report, ErrConfiguration
	}
	client := newHTTPClient(m.tlsConfig, m.config.Profile == "http-test")
	defer client.CloseIdleConnections()
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	response, e := client.Do(req)
	if e != nil {
		return report, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return report, ErrTransport
	}
	if len(response.Header.Values("Content-Encoding")) > 0 {
		return report, ErrReceipt
	}
	if len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return report, ErrReceipt
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return report, ErrReceipt
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return report, ErrReceipt
	}
	var acknowledged receipt
	if lanconfig.StrictObject(raw, &acknowledged, "schemaVersion", "agentId", "sequence", "collectedAt", "receivedAt", "duplicate") != nil {
		return report, ErrReceipt
	}
	now := time.Now().UTC()
	if acknowledged.SchemaVersion != "tracebolt.agent-receipt.v1" || acknowledged.AgentID != m.config.AgentID || acknowledged.Sequence != pending.Sequence || !acknowledged.CollectedAt.Equal(f.Observation.Observation.LastSeen) || acknowledged.ReceivedAt.IsZero() || acknowledged.ReceivedAt.After(now.Add(30*time.Second)) || acknowledged.ReceivedAt.Before(acknowledged.CollectedAt.Add(-30*time.Second)) {
		return report, ErrReceipt
	}
	if state.Acknowledge(pending.Digest) != nil {
		return report, ErrState
	}
	report.Status = "acknowledged"
	report.Duplicate = acknowledged.Duplicate
	return report, nil
}

// collectFrame keeps the basic bundle unchanged and collects it after operations,
// so its generated-at timestamp also bounds the operational collection start.
func collectFrame(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot) (frame, []byte, error) {
	return collectFrameWithCollectors(ctx, c, sequence, collectOperations, packagecollector.Collect)
}

func collectFrameWithCollectors(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (frame, []byte, error) {
	return collectFrameWithSources(ctx, c, sequence, collectOperations, collectPackages, collector.Snapshot)
}

func collectFrameWithSources(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device) (frame, []byte, error) {
	f := frame{SchemaVersion: FrameVersion, Sequence: sequence}
	if c.SchemaVersion == PackageConfigVersion && c.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
		return f, nil, ErrConfiguration
	}
	if ctx.Err() != nil {
		return f, nil, ctx.Err()
	}
	if c.managed() {
		if sequence == 0 || sequence > operational.MaxSafeInteger {
			return f, nil, ErrState
		}
		snapshot := collectOperations(ctx, time.Now().UTC())
		if ctx.Err() != nil {
			return f, nil, ctx.Err()
		}
		if operational.Validate(snapshot) != nil {
			return f, nil, ErrObservation
		}
		f.SchemaVersion, f.Operational = FrameOperationalVersion, &snapshot
		if c.SchemaVersion == PackageConfigVersion {
			bounded, err := operational.TrimForPackageFrame(snapshot)
			if err != nil {
				return f, nil, ErrObservation
			}
			packages, err := collectPackages(ctx, bounded.GenerationID, bounded.CollectedAt)
			if ctx.Err() != nil {
				return f, nil, ctx.Err()
			}
			if err != nil || linuxpackages.Validate(packages) != nil || packages.GenerationID != bounded.GenerationID || !packages.CollectedAt.Equal(bounded.CollectedAt) {
				return f, nil, ErrObservation
			}
			f.SchemaVersion, f.Operational, f.Packages = FramePackagesVersion, &bounded, &packages
		}
	}
	raw, err := bundle.Encode(collectBasic())
	if ctx.Err() != nil {
		return f, nil, ctx.Err()
	}
	if err != nil || json.Unmarshal(raw, &f.Observation) != nil {
		return f, nil, ErrObservation
	}
	body, err := json.Marshal(f)
	if err != nil || len(body) > MaxFrameBytes {
		return f, nil, ErrObservation
	}
	if f.Operational != nil && stale(f, time.Now().UTC()) {
		return f, nil, ErrObservation
	}
	if _, err := decodeFrameForConfig(body, sequence, c); err != nil {
		return f, nil, ErrObservation
	}
	return f, body, nil
}

func decodeFrame(raw []byte, sequence uint64) (frame, error) {
	return decodeFrameForConfig(raw, sequence, Config{SchemaVersion: ConfigVersion})
}
func decodeFrameForConfig(raw []byte, sequence uint64, c Config) (frame, error) {
	var f frame
	if len(raw) == 0 || len(raw) > MaxFrameBytes || rejectDuplicateJSON(raw) != nil {
		return f, ErrState
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return f, ErrState
	}
	want := 3
	if c.SchemaVersion == OperationalConfigVersion || c.complete() {
		want = 4
	} else if c.SchemaVersion == PackageConfigVersion {
		want = 5
	}
	if len(fields) != want {
		return f, ErrState
	}
	for _, key := range []string{"schemaVersion", "sequence", "observation"} {
		if len(fields[key]) == 0 || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return f, ErrState
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF {
		return f, ErrState
	}
	if c.SchemaVersion == OperationalConfigVersion || c.complete() {
		if f.Packages != nil || f.SchemaVersion != FrameOperationalVersion || f.Sequence == 0 || f.Sequence > operational.MaxSafeInteger || (c.CollectionProfile != operational.CollectionProfile && !c.complete()) || f.Operational == nil || len(fields["operational"]) > operational.MaxSnapshotBytes || exactOperationalJSON(fields["operational"]) != nil || operational.Validate(*f.Operational) != nil || f.Observation.Platform != "linux" || f.Operational.CollectedAt.After(f.Observation.GeneratedAt) {
			return f, ErrState
		}
	} else if c.SchemaVersion == PackageConfigVersion {
		if c.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || f.SchemaVersion != FramePackagesVersion || f.Sequence == 0 || f.Sequence > operational.MaxSafeInteger || f.Operational == nil || f.Packages == nil || f.Observation.Platform != "linux" || exactPackageFrameJSON(raw) != nil || len(fields["observation"]) > MaxPackageObservationBytes || len(fields["operational"]) > operational.MaxPackageFrameSnapshotBytes || operational.Validate(*f.Operational) != nil || f.Operational.CollectedAt.After(f.Observation.GeneratedAt) {
			return f, ErrState
		}
		d := f.Observation.Observation
		for _, at := range []time.Time{d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt} {
			if at.After(d.LastSeen) {
				return f, ErrState
			}
		}
		for _, evidence := range d.Evidence {
			if evidence.CollectedAt.After(d.LastSeen) {
				return f, ErrState
			}
		}
		p, err := linuxpackages.Decode(fields["packages"])
		if err != nil || p.GenerationID != f.Operational.GenerationID || !p.CollectedAt.Equal(f.Operational.CollectedAt) {
			return f, ErrState
		}
		op, err := json.Marshal(f.Operational)
		if err != nil || len(op) > operational.MaxPackageFrameSnapshotBytes {
			return f, ErrState
		}
		canonical, err := json.Marshal(f)
		if err != nil || len(canonical) > MaxFrameBytes || len(f.Observation.Version) == 0 || len(f.Observation.Version) > 64 || len(f.Observation.Architecture) == 0 || len(f.Observation.Architecture) > 32 || len(f.Observation.Privacy) > 16 {
			return f, ErrState
		}
	} else if f.SchemaVersion != FrameVersion || f.Operational != nil || f.Packages != nil {
		return f, ErrState
	}
	if f.Sequence != sequence || f.Observation.SchemaVersion != bundle.SchemaVersion || f.Observation.Product != "Tracebolt" || f.Observation.Platform != f.Observation.Observation.Platform || f.Observation.Scope != "single-read-only-local-observation" {
		return f, ErrState
	}
	if e := bundle.ValidateObservation(f.Observation.Observation); e != nil {
		return f, ErrState
	}
	encoded, e := json.Marshal(f.Observation)
	if e != nil || len(encoded) > bundle.MaxBytes || c.SchemaVersion == PackageConfigVersion && len(encoded) > MaxPackageObservationBytes {
		return f, ErrState
	}
	return f, nil
}
func stale(f frame, now time.Time) bool {
	d := f.Observation.Observation
	times := []time.Time{f.Observation.GeneratedAt, d.LastSeen, d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt}
	if f.Operational != nil {
		times = append(times, f.Operational.CollectedAt)
	}
	if f.Packages != nil {
		times = append(times, f.Packages.CollectedAt)
	}
	for _, e := range d.Evidence {
		times = append(times, e.CollectedAt)
	}
	for _, at := range times {
		if at.IsZero() || now.Sub(at) > 2*time.Minute || at.Sub(now) > 30*time.Second || at.After(f.Observation.GeneratedAt) {
			return true
		}
	}
	return false
}
