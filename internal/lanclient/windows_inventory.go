package lanclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/bundle"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsmanaged"
)

type windowsCollector func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error)

func telemetryPath(c Config) string {
	if c.windowsInventory() {
		return WindowsTelemetryPath
	}
	return signedhttp.Path
}

func collectWindowsFrame(ctx context.Context, c Config, sequence uint64, collect windowsCollector) (frame, []byte, error) {
	f := frame{SchemaVersion: FrameWindowsInventoryVersion, Sequence: sequence}
	if !c.windowsInventory() || !windowsTransportAllowed(c) || collect == nil || ctx == nil {
		return f, nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return f, nil, err
	}
	if sequence == 0 || sequence > operational.MaxSafeInteger {
		return f, nil, ErrState
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil || id == [16]byte{} {
		return f, nil, ErrObservation
	}
	generation := "sample_" + hex.EncodeToString(id[:])
	snapshot, device, err := collect(ctx, generation)
	if ctx.Err() != nil {
		return f, nil, ctx.Err()
	}
	if err != nil || windowsmanaged.Validate(snapshot) != nil || snapshot.GenerationID != generation || device.Platform != "windows" || snapshot.CollectedAt.After(device.LastSeen) {
		return f, nil, ErrObservation
	}
	// Both inventory and metrics originate from the single consented report.
	// Its adapter emits a fixed, bounded basic record, without inventory labels.
	raw, err := bundle.Encode(device)
	if err != nil || json.Unmarshal(raw, &f.Observation) != nil {
		return f, nil, ErrObservation
	}
	f.Observation.Privacy = []string{
		"This explicit Windows inventory profile transmits bounded hostname, interface IP, process, service and machine software metadata together with basic metrics using its explicitly selected transport.",
		"Inventory can contain private labels and network topology; inspect each section's source, scope, quality and completeness. It is excluded from AI export.",
		"No event content, command lines, executable paths, owners, process memory, sockets, remote actions or updates are included.",
	}
	if c.Profile == "http-test" {
		f.Observation.Privacy = append(f.Observation.Privacy, "Explicit HTTP-test transport is plaintext and the manager is unauthenticated; signatures provide no confidentiality.")
	}
	f.WindowsInventory = &snapshot
	body, err := json.Marshal(f)
	if err != nil || len(body) > MaxFrameBytes || stale(f, time.Now().UTC()) {
		return f, nil, ErrObservation
	}
	if _, err := decodeFrameForConfig(body, sequence, c); err != nil {
		return f, nil, ErrObservation
	}
	return f, body, nil
}

func validateWindowsFrame(f frame, fields map[string]json.RawMessage, c Config) error {
	if !c.windowsInventory() || !windowsTransportAllowed(c) || (f.SchemaVersion != FrameWindowsInventoryVersion && f.SchemaVersion != FrameWindowsEventsVersion && f.SchemaVersion != FrameWindowsCapabilitiesVersion && f.SchemaVersion != FrameWindowsProcessMetricsVersion && f.SchemaVersion != FrameWindowsNetworkVersion && f.SchemaVersion != FrameWindowsServiceStartupVersion) || f.Sequence == 0 || f.Sequence > operational.MaxSafeInteger || f.WindowsInventory == nil || f.Operational != nil || f.Packages != nil || f.Observation.Platform != "windows" || len(fields["windowsInventory"]) > windowsmanaged.MaxSnapshotBytes || len(fields["observation"]) > MaxWindowsObservationBytes {
		return ErrState
	}
	if validateWindowsEventsFrame(f, fields) != nil || validateWindowsVolumesFrame(f, fields) != nil || validateWindowsProcessMetricsFrame(f, fields) != nil || validateWindowsNetworkFrame(f, fields) != nil || validateWindowsServiceStartupFrame(f, fields) != nil {
		return ErrState
	}
	inventory, err := windowsmanaged.Decode(fields["windowsInventory"])
	if err != nil || exactWindowsObservation(fields["observation"]) != nil {
		return ErrState
	}
	d := f.Observation.Observation
	if inventory.CollectedAt.After(d.LastSeen) || d.LastSeen.After(f.Observation.GeneratedAt) {
		return ErrState
	}
	for _, at := range []time.Time{d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt} {
		if at.IsZero() || at.After(d.LastSeen) {
			return ErrState
		}
	}
	for _, e := range d.Evidence {
		if e.CollectedAt.IsZero() || e.CollectedAt.After(d.LastSeen) {
			return ErrState
		}
	}
	if len(f.Observation.Version) == 0 || len(f.Observation.Version) > 64 || len(f.Observation.Architecture) == 0 || len(f.Observation.Architecture) > 32 || len(f.Observation.Privacy) > 16 {
		return ErrState
	}
	return nil
}

func exactWindowsObservation(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrState
		}
		if s, ok := token.(string); ok && (len(s) > 4096 || strings.ContainsRune(s, utf8.RuneError)) {
			return ErrState
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if exactShape(d, reflect.TypeOf(bundle.Bundle{}), 0) != nil {
		return ErrState
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrState
	}
	return nil
}

func windowsTransportAllowed(c Config) bool {
	return c.Profile == "tls" && !c.InsecureHTTPAcknowledged || c.Profile == "http-test" && c.InsecureHTTPAcknowledged
}
