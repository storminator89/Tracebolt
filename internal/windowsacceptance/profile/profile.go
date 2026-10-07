// Package profile defines the finite, metadata-only manual acceptance contract.
// It grants no authority to start a listener, enroll an identity, or collect data.
package profile

import "errors"

var ErrSelection = errors.New("unsupported Windows acceptance selection")
var ErrObservation = errors.New("invalid Windows acceptance observation")

type Selection struct {
	CollectionProfile string `json:"collectionProfile"`
	Transport         string `json:"transport"`
}

func BasicTLS() Selection     { return Selection{"basic-readonly-v1", "tls"} }
func InventoryTLS() Selection { return Selection{"windows-inventory-v1", "tls"} }

func (s Selection) Validate() error {
	if s == BasicTLS() || s == InventoryTLS() || s == (Selection{"windows-inventory-v1", "http-test"}) {
		return nil
	}
	return ErrSelection
}
func (s Selection) Inventory() bool {
	return s.Validate() == nil && s.CollectionProfile == "windows-inventory-v1"
}
func (s Selection) HTTPTest() bool { return s.Validate() == nil && s.Transport == "http-test" }
func (s Selection) EnrollmentPrefix() string {
	if s.Validate() != nil {
		return ""
	}
	if s.Inventory() {
		return "/v2/windows/enrollment/"
	}
	return "/v2/enrollment/"
}
func (s Selection) TelemetryPath() string {
	if s.Validate() != nil {
		return ""
	}
	if s.Inventory() {
		return "/v1/windows/agent/telemetry"
	}
	return "/v1/agent/telemetry"
}

// Observation retains quality labels only, never inventory rows or metric values.
type Observation struct {
	Frames     uint64 `json:"frames"`
	CPU        string `json:"cpu"`
	Memory     string `json:"memory"`
	Disk       string `json:"disk"`
	Hostname   string `json:"hostname"`
	Processes  string `json:"processes"`
	Services   string `json:"services"`
	Software   string `json:"software"`
	Interfaces string `json:"interfaces"`
}

func ZeroObservation() Observation {
	return Observation{CPU: "not_run", Memory: "not_run", Disk: "not_run", Hostname: "not_run", Processes: "not_run", Services: "not_run", Software: "not_run", Interfaces: "not_run"}
}
func (o Observation) qualities() [8]string {
	return [8]string{o.CPU, o.Memory, o.Disk, o.Hostname, o.Processes, o.Services, o.Software, o.Interfaces}
}
func (o Observation) Validate() error {
	if o.Frames > 64 {
		return ErrObservation
	}
	for _, q := range o.qualities() {
		if o.Frames == 0 {
			if q != "not_run" {
				return ErrObservation
			}
			continue
		}
		switch q {
		case "healthy", "partial", "denied", "unavailable":
		default:
			return ErrObservation
		}
	}
	return nil
}
func (o Observation) Usable() bool {
	if o.Validate() != nil || o.Frames == 0 {
		return false
	}
	for _, q := range o.qualities() {
		if q != "healthy" && q != "partial" {
			return false
		}
	}
	return true
}
