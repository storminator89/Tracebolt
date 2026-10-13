// Package macosinventory is an inactive, separately consented macOS read-only
// source candidate. Importing it never broadens the basic macOS collector.
package macosinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion    = "tracebolt.macos-read-inventory.v1"
	ConsentVersion   = "tracebolt.macos-read-inventory-consent.v1"
	Scope            = "macos-read-inventory-v1"
	MaxBytes         = 512 * 1024
	MaxSourceBytes   = 256 * 1024
	MaxProcesses     = 4096
	MaxReceipts      = 2048
	MaxInterfaces    = 128
	MaxAddresses     = 16
	CollectionBudget = 8 * time.Second
	ProviderBudget   = 2 * time.Second
	CommandBudget    = time.Second
	Privacy          = "Read fixed local hardware model identifier, physical/logical CPU counts and RAM capacity; Installer receipt identifiers; caller-visible process IDs, parent IDs and kernel accounting names; IPv4/IPv6 interface names, MTU, up/running flags and numeric local addresses/prefixes. Process names may be truncated and identify applications; addresses can identify a device or network. Installation receipts do not prove software is still installed. Separate default-off macOS scope bound to a fresh approved identity. No usernames, serials, UUIDs, paths, arguments, environment, logs, MAC addresses, Wi-Fi names, DNS, probes, traffic, software actions or privilege changes are emitted or authorized. Operator-only; no AI/provider export."
	HTTPPrivacy      = "WARNING: HTTP-test exposes hardware, installation receipt identifiers, process labels and numeric network metadata in plaintext. Signatures do not encrypt data or authenticate manager responses. Production requires HTTPS."
	HardwareSource   = "sysctl: hw.model,hw.physicalcpu,hw.logicalcpu,hw.memsize"
	ReceiptSource    = "pkgutil --pkgs-plist: Installer receipt identifiers only"
	ProcessSource    = "ps -A -o ucomm=,pid=,ppid=: caller-visible kernel accounting labels"
	IPv4Source       = "ifconfig -a inet: passive local IPv4 interface context"
	IPv6Source       = "ifconfig -a inet6: passive local IPv6 interface context"
)

var (
	ErrInvalid     = errors.New("macos_inventory_invalid")
	ErrDisabled    = errors.New("macos_inventory_scope_disabled")
	ErrDenied      = errors.New("macos_inventory_access_denied")
	ErrUnavailable = errors.New("macos_inventory_unavailable")
	ErrUnsupported = errors.New("macos_inventory_unsupported_platform")
	ErrMetadata    = errors.New("macos_inventory_invalid_metadata")
	ErrBounds      = errors.New("macos_inventory_bounds")
	ErrBudget      = errors.New("macos_inventory_budget_exhausted")
)

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Request struct {
	Consent       Consent
	SenderBinding string
	GenerationID  string
	CollectedAt   time.Time
}
type Status struct {
	Source  string `json:"source"`
	Quality string `json:"quality"`
	Reason  string `json:"reason"`
}
type Hardware struct {
	Status
	ModelIdentifier     string `json:"modelIdentifier"`
	PhysicalCPUs        uint32 `json:"physicalCPUs"`
	LogicalCPUs         uint32 `json:"logicalCPUs"`
	MemoryCapacityBytes uint64 `json:"memoryCapacityBytes"`
}
type Receipts struct {
	Status
	Identifiers []string `json:"identifiers"`
}
type Process struct {
	PID            uint32 `json:"pid"`
	ParentPID      uint32 `json:"parentPid"`
	AccountingName string `json:"accountingName"`
	NameQuality    string `json:"nameQuality"`
}
type Processes struct {
	Status
	Rows []Process `json:"rows"`
}
type Address struct {
	IP         string `json:"ip"`
	PrefixBits uint8  `json:"prefixBits"`
}
type Interface struct {
	Name      string    `json:"name"`
	MTU       uint32    `json:"mtu"`
	Up        bool      `json:"up"`
	Running   bool      `json:"running"`
	Addresses []Address `json:"addresses"`
}
type Interfaces struct {
	Status
	Rows []Interface `json:"rows"`
}
type Network struct {
	IPv4 Interfaces `json:"ipv4"`
	IPv6 Interfaces `json:"ipv6"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Hardware      Hardware  `json:"hardware"`
	Receipts      Receipts  `json:"receipts"`
	Processes     Processes `json:"processes"`
	Network       Network   `json:"network"`
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func EncodeConsent(c Consent, binding string) ([]byte, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = DecodeConsent(b, binding); e != nil {
		return nil, e
	}
	return b, nil
}
func DecodeConsent(b []byte, binding string) (Consent, error) {
	var c Consent
	if canonical(b, &c, 1024) != nil || c.SchemaVersion != ConsentVersion || c.Scope != Scope || !validHex(binding, 64) || c.SenderBinding != binding || !validHex(c.GrantID, 32) {
		return Consent{}, ErrInvalid
	}
	return c, nil
}
func validStatus(s Status, source string) bool {
	if s.Source != source {
		return false
	}
	if s.Quality == "observed" {
		return s.Reason == ""
	}
	if s.Quality == "denied" {
		return s.Reason == ErrDenied.Error()
	}
	if s.Quality != "unavailable" {
		return false
	}
	switch s.Reason {
	case ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func token(s string, max int, punctuation string) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(punctuation, c)) {
			return false
		}
	}
	return true
}
func accountingName(s string) bool {
	if len(s) == 0 || len(s) > 16 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c > 126 || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}
func validHardware(h Hardware) bool {
	if !validStatus(h.Status, HardwareSource) {
		return false
	}
	if h.Quality != "observed" {
		return h.ModelIdentifier == "" && h.PhysicalCPUs == 0 && h.LogicalCPUs == 0 && h.MemoryCapacityBytes == 0
	}
	return token(h.ModelIdentifier, 64, ",._-") && h.PhysicalCPUs > 0 && h.PhysicalCPUs <= h.LogicalCPUs && h.LogicalCPUs <= 4096 && h.MemoryCapacityBytes > 0 && h.MemoryCapacityBytes <= 1<<60
}
func validReceipts(r Receipts) bool {
	if !validStatus(r.Status, ReceiptSource) || r.Identifiers == nil || len(r.Identifiers) > MaxReceipts {
		return false
	}
	if r.Quality != "observed" {
		return len(r.Identifiers) == 0
	}
	for i, s := range r.Identifiers {
		if !token(s, 256, "._+-") || i > 0 && s <= r.Identifiers[i-1] {
			return false
		}
	}
	return true
}
func validProcesses(p Processes) bool {
	if !validStatus(p.Status, ProcessSource) || p.Rows == nil || len(p.Rows) > MaxProcesses {
		return false
	}
	if p.Quality != "observed" {
		return len(p.Rows) == 0
	}
	// An empty ps -A result cannot establish a successfully observed host.
	if len(p.Rows) == 0 {
		return false
	}
	for i, r := range p.Rows {
		if r.PID > 1<<31-1 || r.ParentPID > 1<<31-1 || i > 0 && r.PID <= p.Rows[i-1].PID {
			return false
		}
		if r.NameQuality == "observed" {
			if !accountingName(r.AccountingName) {
				return false
			}
		} else if r.NameQuality != "unavailable" || r.AccountingName != "" {
			return false
		}
	}
	return true
}
func validInterfaces(v Interfaces, source string, ipv6 bool) bool {
	if !validStatus(v.Status, source) || v.Rows == nil || len(v.Rows) > MaxInterfaces {
		return false
	}
	if v.Quality != "observed" {
		return len(v.Rows) == 0
	}
	if len(v.Rows) == 0 {
		return false
	}
	for i, r := range v.Rows {
		if !token(r.Name, 15, "._-") || r.MTU == 0 || r.MTU > 1<<20 || r.Addresses == nil || len(r.Addresses) > MaxAddresses || i > 0 && r.Name <= v.Rows[i-1].Name {
			return false
		}
		for j, a := range r.Addresses {
			ip, e := netip.ParseAddr(a.IP)
			if e != nil || ip.Zone() != "" || ip.Is6() != ipv6 || ip.Is4In6() || ip.String() != a.IP || int(a.PrefixBits) > ip.BitLen() || j > 0 && addressKey(a) <= addressKey(r.Addresses[j-1]) {
				return false
			}
		}
	}
	return true
}
func addressKey(a Address) string { return a.IP + "/" + string(rune(a.PrefixBits)) }
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !validHex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !validHex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validHardware(s.Hardware) || !validReceipts(s.Receipts) || !validProcesses(s.Processes) || !validInterfaces(s.Network.IPv4, IPv4Source, false) || !validInterfaces(s.Network.IPv6, IPv6Source, true) {
		return ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxBytes {
		return ErrBounds
	}
	return nil
}
func Encode(s Snapshot) ([]byte, error) {
	if e := Validate(s); e != nil {
		return nil, e
	}
	return json.Marshal(s)
}
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func ValidateBinding(s Snapshot, generation, grant string, at time.Time) error {
	if Validate(s) != nil || s.GenerationID != generation || s.GrantID != grant || !s.CollectedAt.Equal(at) {
		return ErrInvalid
	}
	return nil
}
func emptyStatus(source, reason string) Status {
	q := "unavailable"
	if reason == ErrDenied.Error() {
		q = "denied"
	}
	return Status{source, q, reason}
}
func EmptyHardware(reason string) Hardware {
	return Hardware{Status: emptyStatus(HardwareSource, reason)}
}
func EmptyReceipts(reason string) Receipts {
	return Receipts{emptyStatus(ReceiptSource, reason), []string{}}
}
func EmptyProcesses(reason string) Processes {
	return Processes{emptyStatus(ProcessSource, reason), []Process{}}
}
func EmptyInterfaces(source, reason string) Interfaces {
	return Interfaces{emptyStatus(source, reason), []Interface{}}
}
func EmptyNetwork(reason string) Network {
	return Network{EmptyInterfaces(IPv4Source, reason), EmptyInterfaces(IPv6Source, reason)}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyHardware(reason), EmptyReceipts(reason), EmptyProcesses(reason), EmptyNetwork(reason)}
}
func sortInterfaces(v *Interfaces) {
	sort.Slice(v.Rows, func(i, j int) bool { return v.Rows[i].Name < v.Rows[j].Name })
	for i := range v.Rows {
		sort.Slice(v.Rows[i].Addresses, func(a, b int) bool { return addressKey(v.Rows[i].Addresses[a]) < addressKey(v.Rows[i].Addresses[b]) })
	}
}
