// Package endpointidentity holds bounded, untrusted, operator-only endpoint
// display metadata. It grants no collection consent, identity or attestation.
// The reviewed Linux source is invoked only through explicit consent gating.
// Transport, protected local administration and retention are separate layers.
package endpointidentity

import (
	"errors"
	"time"
)

const (
	SchemaVersion                  = "tracebolt.endpoint-identity.v1"
	Scope                          = "agent-visible-linux-hostname-and-interface-addresses"
	MaxSnapshotBytes               = 8 << 10
	MaxHostnameBytes               = 253
	MaxInterfaceNameBytes          = 15 // Linux IFNAMSIZ minus terminating NUL.
	MaxInterfaces                  = 32
	MaxAddressesPerInterface       = 32
	MaxAddresses                   = 128
	MaxSafeInteger           int64 = 1<<53 - 1
	CollectionTimeout              = 5 * time.Second
)

var (
	ErrInvalidSnapshot  = errors.New("endpoint_identity_invalid")
	ErrSnapshotLimit    = errors.New("endpoint_identity_limit")
	ErrInvalidInput     = errors.New("endpoint_identity_invalid_input")
	ErrSourceMissing    = errors.New("endpoint_identity_source_missing")
	ErrPermissionDenied = errors.New("endpoint_identity_permission_denied")
	ErrNotSupported     = errors.New("endpoint_identity_not_supported")
	ErrInvalidSource    = errors.New("endpoint_identity_invalid_source")
	ErrItemLimit        = errors.New("endpoint_identity_item_limit")
	ErrByteLimit        = errors.New("endpoint_identity_byte_limit")
)

type Coverage string

const (
	Complete Coverage = "complete"
	Partial  Coverage = "partial"
	Failed   Coverage = "failed"
)

type Reason string

const (
	ReasonNone               Reason = "none"
	ReasonSourceMissing      Reason = "source_missing"
	ReasonPermissionDenied   Reason = "permission_denied"
	ReasonNotSupported       Reason = "not_supported"
	ReasonTimeout            Reason = "timeout"
	ReasonInvalidSource      Reason = "invalid_source"
	ReasonReadFailed         Reason = "read_failed"
	ReasonItemLimit          Reason = "item_limit"
	ReasonByteLimit          Reason = "byte_limit"
	ReasonCollectorBusy      Reason = "collector_busy"
	ReasonNotCollected       Reason = "not_collected"
	ReasonAddressUnavailable Reason = "address_unavailable"
)

type Snapshot struct {
	SchemaVersion    string           `json:"schemaVersion"`
	GenerationID     string           `json:"generationId"`
	CollectedAt      time.Time        `json:"collectedAt"`
	DurationMS       int64            `json:"durationMs"`
	Scope            string           `json:"scope"`
	ReportedHostname Hostname         `json:"reportedHostname"`
	Interfaces       InterfaceSection `json:"interfaces"`
}

type Hostname struct {
	Coverage Coverage `json:"coverage"`
	Reason   Reason   `json:"reason"`
	Value    *string  `json:"value"`
}

// SectionMeta counts interface rows or assigned addresses, never all host
// interfaces across namespaces. A partial interface section still has an exact
// interface-row count: enumeration succeeded but some address reads did not.
type SectionMeta struct {
	Coverage      Coverage `json:"coverage"`
	Reason        Reason   `json:"reason"`
	ObservedCount *uint32  `json:"observedCount"`
	CountExact    bool     `json:"countExact"`
}
type InterfaceSection struct {
	Meta  SectionMeta `json:"meta"`
	Items []Interface `json:"items"`
}
type AddressSection struct {
	Meta  SectionMeta `json:"meta"`
	Items []Address   `json:"items"`
}
type Interface struct {
	Index    uint32 `json:"index"`
	Name     string `json:"name"`
	Up       bool   `json:"up"`
	Loopback bool   `json:"loopback"`
	// HardwareKind is always unknown in v1. Names and address ranges do not
	// establish whether the interface is physical, virtual, a bridge or a VPN.
	HardwareKind string     `json:"hardwareKind"`
	Addresses    AddressSet `json:"addresses"`
}
type AddressSet struct {
	IPv4 AddressSection `json:"ipv4"`
	IPv6 AddressSection `json:"ipv6"`
}
type Address struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	// Scope is an address-range label, not a reachability claim. "other" does
	// not establish that the address is globally reachable.
	Scope string `json:"scope"`
}

func Empty(generation string, at time.Time, reason Reason) Snapshot {
	if !failureReasonValid(reason) {
		reason = ReasonReadFailed
	}
	return Snapshot{SchemaVersion: SchemaVersion, GenerationID: generation, CollectedAt: at, Scope: Scope,
		ReportedHostname: Hostname{Coverage: Failed, Reason: reason}, Interfaces: failedInterfaces(reason)}
}
func failedInterfaces(reason Reason) InterfaceSection {
	return InterfaceSection{Meta: SectionMeta{Coverage: Failed, Reason: reason}, Items: []Interface{}}
}
func failedAddresses(reason Reason) AddressSection {
	return AddressSection{Meta: SectionMeta{Coverage: Failed, Reason: reason}, Items: []Address{}}
}
func completeMeta(n int) SectionMeta {
	count := uint32(n)
	return SectionMeta{Coverage: Complete, Reason: ReasonNone, ObservedCount: &count, CountExact: true}
}
