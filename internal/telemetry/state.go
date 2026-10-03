// Package telemetry implements an explicitly local, in-memory development
// preview. It does not authenticate or enroll endpoints and has no persistence.
package telemetry

import (
	"bytes"
	"fmt"
	"localrmm/internal/bundle"
	"localrmm/internal/model"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxBodyBytes = bundle.MaxBytes
	MaxSampleAge = 2 * time.Minute
	FutureSkew   = 5 * time.Second
	DeviceID     = "sandbox-local"
)

// Error is a safe public error: it never includes payload text or device data.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string     { return e.Message }
func invalid(message string) error { return &Error{Code: "invalid_bundle", Message: message} }

type Receipt struct {
	ManagerStartedAt time.Time `json:"managerStartedAt"`
	DeviceID         string    `json:"deviceId"`
	Sequence         uint64    `json:"sequence"`
	CollectedAt      time.Time `json:"collectedAt"`
	ReceivedAt       time.Time `json:"receivedAt"`
}
type Status struct {
	ManagerStartedAt time.Time  `json:"managerStartedAt"`
	Mode             string     `json:"mode"`
	State            string     `json:"state"`
	DeviceID         string     `json:"deviceId"`
	AcceptedSamples  uint64     `json:"acceptedSamples"`
	CollectedAt      *time.Time `json:"collectedAt"`
	ReceivedAt       *time.Time `json:"receivedAt"`
	MaxAgeSeconds    int64      `json:"maxAgeSeconds"`
}
type State struct {
	startedAt   time.Time
	mu          sync.RWMutex
	device      model.Device
	generatedAt time.Time
	receipt     Receipt
}

func NewState() *State { return &State{startedAt: time.Now().UTC()} }

// Accept replaces one observation atomically. A rejected sample never refreshes
// timestamps. Replay protection is scoped to this manager process; no device
// identity, credentials, or replay database are created.
func (s *State) Accept(raw []byte, receivedAt time.Time) (Receipt, error) {
	b, err := decodeBundle(raw, receivedAt)
	if err != nil {
		return Receipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receipt.Sequence != 0 && (!b.Observation.LastSeen.After(s.receipt.CollectedAt) || !b.GeneratedAt.After(s.generatedAt)) {
		return Receipt{}, &Error{Code: "replayed_sample", Message: "Duplicate or out-of-order observation rejected."}
	}
	// Map identity on the receiving side as well as checking the input contract.
	d := b.Observation
	d.ID, d.Name, d.Platform = DeviceID, "Local sandbox", "linux"
	d.Site, d.Group, d.Source = "Cloud sandbox", "Local observations", "sandbox"
	d.Status, d.IP, d.Synthetic = "unknown", nil, false
	s.device, s.generatedAt = d, b.GeneratedAt
	s.receipt = Receipt{ManagerStartedAt: s.startedAt, DeviceID: DeviceID, Sequence: s.receipt.Sequence + 1, CollectedAt: d.LastSeen, ReceivedAt: receivedAt.UTC()}
	return s.receipt, nil
}

func (s *State) Status(now time.Time) Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Status{ManagerStartedAt: s.startedAt, Mode: "managed-preview", State: "awaiting", DeviceID: DeviceID, AcceptedSamples: s.receipt.Sequence, MaxAgeSeconds: int64(MaxSampleAge / time.Second)}
	if s.receipt.Sequence != 0 {
		collected, received := s.receipt.CollectedAt, s.receipt.ReceivedAt
		st.CollectedAt, st.ReceivedAt = &collected, &received
		st.State = "fresh"
		if s.stale(now) {
			st.State = "stale"
		}
	}
	return st
}
func (s *State) stale(now time.Time) bool {
	times := []time.Time{s.receipt.CollectedAt, s.receipt.ReceivedAt, s.device.CPU.CollectedAt, s.device.Memory.CollectedAt, s.device.Disk.CollectedAt}
	for _, evidence := range s.device.Evidence {
		times = append(times, evidence.CollectedAt)
	}
	for _, at := range times {
		if now.Sub(at) > MaxSampleAge || at.Sub(now) > FutureSkew {
			return true
		}
	}
	return false
}

// Device is a copy for the existing UI contract. Overall device health is always
// unknown, even when all observed metrics are valid. No collector is invoked.
func (s *State) Device(now time.Time) model.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.receipt.Sequence == 0 {
		return awaitingDevice()
	}
	d := cloneDevice(s.device)
	quality := "healthy"
	if s.stale(now) {
		quality = "stale"
		for _, m := range []*model.Metric{&d.CPU, &d.Memory, &d.Disk} {
			if m.Quality == "healthy" {
				m.Quality = "stale"
			}
		}
		for i := range d.Evidence {
			if d.Evidence[i].Quality == "healthy" {
				d.Evidence[i].Quality = "stale"
			}
		}
	}
	d.Capabilities = append(d.Capabilities, transportCapability())
	d.Evidence = append(d.Evidence, model.Evidence{ID: "local-agent-transport", Title: "Local agent transport", Source: "loopback development ingress", Quality: quality, CollectedAt: s.receipt.CollectedAt, Value: fmt.Sprintf("One-shot local agent sample #%d", s.receipt.Sequence), Detail: "Linux support bundle received through the loopback development transport at " + s.receipt.ReceivedAt.Format(time.RFC3339Nano) + ". The intended separate dev-agent flow is checked in the two-process smoke test; the manager does not authenticate the sender. This is not proof of continuous availability, enrolled identity, or whole-device health."})
	return d
}
func transportCapability() model.Capability {
	return model.Capability{ID: "local_transport", Name: "Local agent transport", Status: "limited", Detail: "One-shot loopback development preview only. No enrolled identity, persistent agent, service installation, remote access, or continuous availability monitoring."}
}
func awaitingDevice() model.Device {
	m := model.Metric{Unit: "%", Quality: "unknown", Source: "Awaiting one-shot local dev-agent observation"}
	return model.Device{ID: DeviceID, Name: "Local sandbox", Platform: "linux", OS: "Awaiting agent observation", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", AgentVersion: "unknown", CPU: m, Memory: m, Disk: m, Uptime: "Unknown", Tags: []string{"sandbox", "read-only", "local-only"}, Trend: []float64{}, CaseIDs: []string{}, Evidence: []model.Evidence{}, Capabilities: []model.Capability{transportCapability(), {ID: "systemd", Name: "Service inventory", Status: "unsupported", Detail: "Service managers are not queried."}, {ID: "journal", Name: "System logs", Status: "unsupported", Detail: "System logs are not collected."}, {ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "No command execution or remote control."}}}
}
func cloneDevice(d model.Device) model.Device {
	for _, m := range []*model.Metric{&d.CPU, &d.Memory, &d.Disk} {
		if m.Value != nil {
			v := *m.Value
			m.Value = &v
		}
	}
	d.Tags = append([]string{}, d.Tags...)
	d.Capabilities = append([]model.Capability{}, d.Capabilities...)
	d.Evidence = append([]model.Evidence{}, d.Evidence...)
	d.Trend = append([]float64{}, d.Trend...)
	d.CaseIDs = append([]string{}, d.CaseIDs...)
	return d
}

func decodeBundle(raw []byte, receivedAt time.Time) (bundle.Bundle, error) {
	var b bundle.Bundle
	if len(raw) > MaxBodyBytes {
		return b, &Error{Code: "payload_too_large", Message: "Telemetry exceeds the 64 KiB limit."}
	}
	if len(raw) == 0 || receivedAt.IsZero() {
		return b, invalid("A bounded observation and receipt time are required.")
	}
	if err := strictJSON(raw, &b); err != nil {
		return b, invalid("Telemetry does not match the strict support-bundle schema.")
	}
	validText := func(s string, max int) bool {
		return len(s) <= max && utf8.ValidString(s) && !bytes.ContainsRune([]byte(s), '\x00') && !containsControls(s)
	}
	if b.SchemaVersion != bundle.SchemaVersion || b.Product != "Tracebolt" || b.Version != model.Version || b.Platform != "linux" || b.Scope != "single-read-only-local-observation" {
		return b, invalid("Unsupported Linux preview bundle contract.")
	}
	switch b.Architecture {
	case "amd64", "arm64", "386", "arm", "ppc64", "ppc64le", "riscv64", "s390x", "loong64":
	default:
		return b, invalid("Unsupported architecture label.")
	}
	if !validText(b.Validation.PlatformExecution, 4096) || !validText(b.Validation.Acceptance, 4096) || len(b.Privacy) > 16 {
		return b, invalid("Invalid bundle metadata.")
	}
	for _, p := range b.Privacy {
		if !validText(p, 4096) {
			return b, invalid("Invalid privacy metadata.")
		}
	}
	if b.Observation.Platform != "linux" {
		return b, invalid("Only the fixed Linux preview role is accepted.")
	}
	// Existing exporter validates role labels, metadata bounds, privacy fields,
	// finite metric ranges, quality, capability states and evidence uniqueness.
	if _, err := bundle.Encode(b.Observation); err != nil {
		return b, invalid("Invalid local observation contract.")
	}
	if err := linuxContract(b.Observation); err != nil {
		return b, err
	}
	times := []time.Time{b.GeneratedAt, b.Observation.LastSeen, b.Observation.CPU.CollectedAt, b.Observation.Memory.CollectedAt, b.Observation.Disk.CollectedAt}
	for _, e := range b.Observation.Evidence {
		times = append(times, e.CollectedAt)
	}
	for _, at := range times {
		if at.IsZero() {
			return b, invalid("Every observation requires a collection timestamp.")
		}
		if at.Sub(receivedAt) > FutureSkew {
			return b, &Error{Code: "future_sample", Message: "Future observation timestamp rejected."}
		}
		if receivedAt.Sub(at) > MaxSampleAge {
			return b, &Error{Code: "stale_sample", Message: "Observation is too old for ingestion."}
		}
		if at.After(b.GeneratedAt) {
			return b, invalid("Observation timestamp is later than bundle generation.")
		}
	}
	for _, at := range times[2:] {
		if at.After(b.Observation.LastSeen) {
			return b, invalid("Field collection timestamp is later than the observation.")
		}
	}
	return b, nil
}
func containsControls(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
func linuxContract(d model.Device) error {
	caps := map[string]bool{"cpu": true, "memory": true, "disk": true, "os": true, "uptime": true, "host_inventory": true, "systemd": true, "journal": true, "remote_actions": true}
	for _, c := range d.Capabilities {
		if !caps[c.ID] {
			return invalid("Unknown or duplicate Linux capability.")
		}
		delete(caps, c.ID)
		if (c.ID == "systemd" || c.ID == "journal" || c.ID == "remote_actions") && c.Status != "unsupported" {
			return invalid("Unsupported capability cannot be claimed.")
		}
		if c.ID == "host_inventory" && c.Status != "limited" {
			return invalid("Physical host attribution is not established.")
		}
	}
	if len(caps) != 0 {
		return invalid("Incomplete Linux capability disclosure.")
	}
	evidence := map[string]bool{"sandbox-cpu": true, "sandbox-memory": true, "sandbox-disk": true, "sandbox-os": true, "sandbox-uptime": true, "sandbox-scope": true}
	for _, e := range d.Evidence {
		if !evidence[e.ID] {
			return invalid("Unknown or duplicate Linux evidence.")
		}
		delete(evidence, e.ID)
	}
	if len(evidence) != 0 {
		return invalid("Incomplete Linux evidence disclosure.")
	}
	return nil
}
