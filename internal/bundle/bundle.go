// Package bundle formats a bounded, local-only diagnostic observation for manual review.
// It does not collect more data or transmit the bundle anywhere.
package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/model"
	"math"
	"runtime"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.support.v1"
const MaxBytes = 64 * 1024

type Validation struct {
	PlatformExecution string `json:"platformExecution"`
	Acceptance        string `json:"acceptance"`
}
type Bundle struct {
	SchemaVersion string       `json:"schemaVersion"`
	Product       string       `json:"product"`
	Version       string       `json:"version"`
	GeneratedAt   time.Time    `json:"generatedAt"`
	Platform      string       `json:"platform"`
	Architecture  string       `json:"architecture"`
	Scope         string       `json:"scope"`
	Validation    Validation   `json:"validation"`
	Privacy       []string     `json:"privacy"`
	Observation   model.Device `json:"observation"`
}

func newBundle(d model.Device) Bundle {
	return Bundle{SchemaVersion: SchemaVersion, Product: "Tracebolt", Version: model.Version, GeneratedAt: time.Now().UTC(), Platform: d.Platform, Architecture: runtime.GOARCH, Scope: "single-read-only-local-observation", Validation: Validation{PlatformExecution: "Collector invoked once on this process platform; inspect per-field quality and capability details.", Acceptance: "Windows/macOS native acceptance is not established by a cross-build or a support bundle. Linux integration is limited to sandbox-visible observations."}, Privacy: []string{"Creating this bundle does not transmit it or install a service. A separately configured sender may transmit it.", "No hostname, IP address, serial number, account, process inventory, logs, credentials or personal file contents are intentionally collected.", "OS/build, utilization, capacity, uptime and collection times may reveal system characteristics. Review the JSON before sharing it.", "Device IDs and labels are fixed role labels, not machine identifiers."}, Observation: d}
}
func Encode(d model.Device) ([]byte, error) {
	// Preserve schema array types even for an intentionally empty local sample.
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.Capabilities == nil {
		d.Capabilities = []model.Capability{}
	}
	if d.Evidence == nil {
		d.Evidence = []model.Evidence{}
	}
	if d.Trend == nil {
		d.Trend = []float64{}
	}
	if d.CaseIDs == nil {
		d.CaseIDs = []string{}
	}
	if err := ValidateObservation(d); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(newBundle(d), "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("support bundle exceeds %d-byte limit", MaxBytes)
	}
	return b, nil
}

// ValidateObservation applies the deterministic identifier-minimizing observation
// policy without generating an envelope or consulting the clock. Callers must
// additionally enforce their actual enclosing contract's aggregate byte bound.
func ValidateObservation(d model.Device) error {
	if d.Synthetic || d.IP != nil || len(d.CaseIDs) != 0 || len(d.Trend) != 0 {
		return errors.New("support bundles accept only identifier-free local observations")
	}
	if err := validateMetadata(d); err != nil {
		return err
	}
	if d.Status != "unknown" {
		return errors.New("incomplete observations cannot assert device health")
	}
	if d.Platform != "linux" && d.Platform != "macos" && d.Platform != "windows" {
		return errors.New("unsupported bundle platform")
	}
	for _, m := range []model.Metric{d.CPU, d.Memory, d.Disk} {
		if m.Unit != "%" || !validQuality(m.Quality) {
			return errors.New("invalid metric metadata")
		}
		if m.Quality == "healthy" && m.Value == nil {
			return errors.New("valid metric quality requires a value")
		}
		if m.Value != nil && (math.IsNaN(*m.Value) || math.IsInf(*m.Value, 0) || *m.Value < 0 || *m.Value > 100) {
			return errors.New("metric is outside finite percentage bounds")
		}
		if m.Value != nil && (m.Quality == "unknown" || m.Quality == "denied") {
			return errors.New("unavailable metric must not contain a value")
		}
	}
	switch d.ID {
	case "sandbox-local", "local-windows", "local-macos":
	default:
		return errors.New("unexpected local role label")
	}
	if d.Source != "sandbox" && d.Source != "local" {
		return errors.New("unsupported observation source")
	}
	seen := map[string]bool{}
	for _, e := range d.Evidence {
		if e.ID == "" || seen[e.ID] || e.Synthetic || !validQuality(e.Quality) {
			return errors.New("invalid local evidence identity")
		}
		seen[e.ID] = true
	}
	return nil
}

func validQuality(q string) bool {
	return q == "healthy" || q == "stale" || q == "unknown" || q == "denied"
}

// Only trusted collector output is accepted. Fixed role metadata cannot be
// repurposed as a hostname/account field; free-text observations remain bounded
// and must still be reviewed before the operator shares a bundle.
func validateMetadata(d model.Device) error {
	roles := map[string][5]string{
		"linux":   {"sandbox-local", "sandbox", "Local sandbox", "Cloud sandbox", "Local observations"},
		"windows": {"local-windows", "local", "Local Windows", "Local machine", "Local observations"},
		"macos":   {"local-macos", "local", "Local macOS", "Local machine", "Local observations"},
	}
	role, ok := roles[d.Platform]
	if !ok || d.ID != role[0] || d.Source != role[1] || d.Name != role[2] || d.Site != role[3] || d.Group != role[4] {
		return errors.New("observation role metadata does not match the fixed platform contract")
	}
	valid := func(s string, n int) bool { return len(s) <= n && utf8.ValidString(s) }
	if !valid(d.OS, 512) || !valid(d.Uptime, 128) || !valid(d.AgentVersion, 64) || len(d.Tags) > 64 || len(d.Capabilities) > 64 || len(d.Evidence) > 64 {
		return errors.New("observation exceeds schema bounds")
	}
	tags := map[string]bool{"sandbox": true, "read-only": true, "local-only": true, "native-unverified": true}
	for _, tag := range d.Tags {
		if !tags[tag] || (tag == "sandbox" && d.Platform != "linux") || (tag == "native-unverified" && d.Platform == "linux") {
			return errors.New("unexpected role tag")
		}
	}
	for _, m := range []model.Metric{d.CPU, d.Memory, d.Disk} {
		if !valid(m.Source, 4096) {
			return errors.New("metric source exceeds schema bounds")
		}
	}
	for _, e := range d.Evidence {
		if !valid(e.ID, 96) || !valid(e.Title, 256) || !valid(e.Source, 4096) || !valid(e.Detail, 4096) || !valid(e.Value, 4096) {
			return errors.New("evidence exceeds schema bounds")
		}
	}
	for _, c := range d.Capabilities {
		if !valid(c.ID, 96) || !valid(c.Name, 256) || !valid(c.Detail, 4096) {
			return errors.New("capability exceeds schema bounds")
		}
		if c.Status != "supported" && c.Status != "limited" && c.Status != "unsupported" && c.Status != "denied" {
			return errors.New("invalid capability state")
		}
	}
	return nil
}
