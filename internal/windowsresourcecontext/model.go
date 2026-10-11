// Package windowsresourcecontext carries separately consented, fixed local CPU
// inventory and memory context. It does not replace the existing CPU sampler.
package windowsresourcecontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-resource-context.v1"
const ConsentVersion = "tracebolt.windows-resource-context-consent.v1"
const Scope = "windows-resource-context-v1"
const MaxBytes = 5 * 1024
const MaxProcessors = 4
const MaxStringUnits = 128
const MaxProcessorCount = 65535
const MaxPagefiles = 32
const CollectionBudget = 5 * time.Second
const ProviderBudget = time.Second
const Privacy = "Read and send fixed local CPU model labels, architecture, core and logical-processor counts; SMBIOS-reported physically installed RAM separately from OS-usable physical total/available RAM; committed-memory current/limit with derived remaining commit capacity; aggregate pagefile count, allocated capacity and current in-use bytes. Separate default-off local scope; earlier scopes and receipts do not authorize it. CPU inventory does not change the existing observed-group CPU utilization sampler. Commit usage is not pagefile usage; installed RAM and OS-usable physical RAM are different sources. No paging-I/O, thrashing or memory-health verdict. No CPU identifiers/serials, pagefile names/paths, per-process data, summed pagefile peaks, raw firmware, remote queries, arbitrary WMI, writes or privilege changes. Operator-only; no AI/provider export."
const HTTPPrivacy = "WARNING: HTTP-test sends CPU model/architecture and source-labeled core/logical counts, SMBIOS-installed and OS-usable/available RAM, committed-memory current/limit/derived remaining capacity, and aggregate pagefile count/allocated/in-use bytes in plaintext; pagefile names and paths are excluded. Network observers can read it; signatures do not encrypt metadata or authenticate manager responses. Production requires HTTPS."

var ErrInvalid = errors.New("windows_resource_context_invalid")
var ErrDisabled = errors.New("windows_resource_context_scope_disabled")
var ErrDenied = errors.New("windows_resource_context_access_denied")
var ErrUnavailable = errors.New("windows_resource_context_unavailable")
var ErrUnsupported = errors.New("windows_resource_context_unsupported_platform")
var ErrMetadata = errors.New("windows_resource_context_invalid_metadata")
var ErrBounds = errors.New("windows_resource_context_bounds")
var ErrPartial = errors.New("windows_resource_context_partial_result")
var ErrBudget = errors.New("windows_resource_context_budget_exhausted")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Field struct {
	Value   *string `json:"value"`
	Quality string  `json:"quality"`
}
type CountField struct {
	Value   *uint32 `json:"value"`
	Quality string  `json:"quality"`
}
type Processor struct {
	Name              Field      `json:"name"`
	Architecture      Field      `json:"architecture"`
	Cores             CountField `json:"cores"`
	LogicalProcessors CountField `json:"logicalProcessors"`
}
type Processors struct {
	Quality                string      `json:"quality"`
	Reason                 string      `json:"reason"`
	Source                 string      `json:"source"`
	Rows                   []Processor `json:"rows"`
	TotalCores             *uint32     `json:"totalCores"`
	TotalLogicalProcessors *uint32     `json:"totalLogicalProcessors"`
}
type InstalledMemory struct {
	Quality        string  `json:"quality"`
	Reason         string  `json:"reason"`
	Source         string  `json:"source"`
	InstalledBytes *string `json:"installedBytes"`
}
type Memory struct {
	Quality                string  `json:"quality"`
	Reason                 string  `json:"reason"`
	Source                 string  `json:"source"`
	CommitTotalBytes       *string `json:"commitTotalBytes"`
	CommitLimitBytes       *string `json:"commitLimitBytes"`
	PhysicalTotalBytes     *string `json:"physicalTotalBytes"`
	PhysicalAvailableBytes *string `json:"physicalAvailableBytes"`
	PageSizeBytes          *string `json:"pageSizeBytes"`
}
type Pagefiles struct {
	Quality         string  `json:"quality"`
	Reason          string  `json:"reason"`
	Source          string  `json:"source"`
	Count           *uint32 `json:"count"`
	TotalBytes      *string `json:"totalBytes"`
	TotalInUseBytes *string `json:"totalInUseBytes"`
}
type Snapshot struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Scope           string          `json:"scope"`
	GrantID         string          `json:"grantId"`
	GenerationID    string          `json:"generationId"`
	CollectedAt     time.Time       `json:"collectedAt"`
	Processors      Processors      `json:"processors"`
	InstalledMemory InstalledMemory `json:"installedMemory"`
	Memory          Memory          `json:"memory"`
	Pagefiles       Pagefiles       `json:"pagefiles"`
}
type Request struct {
	Consent       Consent
	SenderBinding string
	GenerationID  string
	CollectedAt   time.Time
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
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
func DecodeConsent(raw []byte, binding string) (Consent, error) {
	var c Consent
	if canonical(raw, &c, 1024) != nil || c.SchemaVersion != ConsentVersion || c.Scope != Scope || !hex(binding, 64) || c.SenderBinding != binding || !hex(c.GrantID, 32) {
		return Consent{}, ErrInvalid
	}
	return c, nil
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
func validReason(s string) bool {
	switch s {
	case "", ErrDenied.Error(), ErrUnavailable.Error(), ErrUnsupported.Error(), ErrMetadata.Error(), ErrBounds.Error(), ErrPartial.Error(), ErrBudget.Error():
		return true
	}
	return false
}
func validLabel(s string, units int) bool {
	if s == "" || !utf8.ValidString(s) || len(s) > units*4 {
		return false
	}
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == 0xfffd {
			return false
		}
		n++
		if r > 0xffff {
			n++
		}
	}
	return n <= units
}
func validField(f Field) bool {
	if f.Quality == "observed" {
		return f.Value != nil && validLabel(*f.Value, MaxStringUnits)
	}
	return f.Value == nil && (f.Quality == "empty" || f.Quality == "denied" || f.Quality == "unavailable")
}
func validCount(f CountField) bool {
	if f.Quality == "observed" {
		return f.Value != nil && *f.Value > 0 && *f.Value <= MaxProcessorCount
	}
	return f.Value == nil && (f.Quality == "denied" || f.Quality == "unavailable")
}
func validArchitecture(f Field) bool {
	if !validField(f) || f.Quality == "empty" {
		return false
	}
	if f.Value == nil {
		return true
	}
	switch *f.Value {
	case "x86", "MIPS", "Alpha", "PowerPC", "ARM", "ia64", "x64", "ARM64":
		return true
	}
	return false
}
func unavailableQuality(reason string) string {
	if reason == ErrDenied.Error() {
		return "denied"
	}
	return "unavailable"
}
func validFailure(q, reason string) bool {
	return validReason(reason) && reason != "" && q == unavailableQuality(reason)
}
func validProcessors(p Processors) bool {
	if p.Source != "Win32_Processor" || p.Rows == nil || len(p.Rows) > MaxProcessors || !validReason(p.Reason) {
		return false
	}
	if p.Quality == "denied" || p.Quality == "unavailable" {
		return validFailure(p.Quality, p.Reason) && len(p.Rows) == 0 && p.TotalCores == nil && p.TotalLogicalProcessors == nil
	}
	if len(p.Rows) == 0 {
		return false
	}
	partial, counts := false, true
	var cores, logical uint32
	for _, r := range p.Rows {
		if !validField(r.Name) || !validArchitecture(r.Architecture) || !validCount(r.Cores) || !validCount(r.LogicalProcessors) {
			return false
		}
		partial = partial || r.Name.Quality == "denied" || r.Name.Quality == "unavailable" || r.Architecture.Quality != "observed" || r.Cores.Quality != "observed" || r.LogicalProcessors.Quality != "observed"
		if r.Cores.Value == nil || r.LogicalProcessors.Value == nil {
			counts = false
		} else {
			cores += *r.Cores.Value
			logical += *r.LogicalProcessors.Value
		}
	}
	if counts {
		if p.TotalCores == nil || p.TotalLogicalProcessors == nil || *p.TotalCores != cores || *p.TotalLogicalProcessors != logical {
			return false
		}
	} else if p.TotalCores != nil || p.TotalLogicalProcessors != nil {
		return false
	}
	return (!partial && p.Quality == "observed" && p.Reason == "") || (partial && p.Quality == "partial" && p.Reason == ErrPartial.Error())
}
func decimal(p *string) (uint64, bool) {
	if p == nil || len(*p) == 0 || len(*p) > 20 || len(*p) > 1 && (*p)[0] == '0' {
		return 0, false
	}
	for _, c := range *p {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(*p, 10, 64)
	return n, e == nil
}
func validInstalledMemory(m InstalledMemory) bool {
	if m.Source != "GetPhysicallyInstalledSystemMemory" {
		return false
	}
	if m.Quality != "observed" {
		return m.InstalledBytes == nil && validFailure(m.Quality, m.Reason)
	}
	n, ok := decimal(m.InstalledBytes)
	return ok && n > 0 && n%1024 == 0 && m.Reason == ""
}
func validPageSize(n uint64) bool { return n >= 1024 && n <= 1<<30 && n&(n-1) == 0 }
func validMemory(m Memory) bool {
	if m.Source != "K32GetPerformanceInfo" {
		return false
	}
	if m.Quality != "observed" {
		return m.CommitTotalBytes == nil && m.CommitLimitBytes == nil && m.PhysicalTotalBytes == nil && m.PhysicalAvailableBytes == nil && m.PageSizeBytes == nil && validFailure(m.Quality, m.Reason)
	}
	ct, a := decimal(m.CommitTotalBytes)
	cl, b := decimal(m.CommitLimitBytes)
	pt, c := decimal(m.PhysicalTotalBytes)
	pa, d := decimal(m.PhysicalAvailableBytes)
	ps, e := decimal(m.PageSizeBytes)
	return a && b && c && d && e && m.Reason == "" && validPageSize(ps) && cl > 0 && pt > 0 && ct <= cl && pa <= pt && ct%ps == 0 && cl%ps == 0 && pt%ps == 0 && pa%ps == 0
}
func validPagefiles(p Pagefiles) bool {
	if p.Source != "EnumPageFilesW" {
		return false
	}
	if p.Quality != "observed" {
		return p.Count == nil && p.TotalBytes == nil && p.TotalInUseBytes == nil && validFailure(p.Quality, p.Reason)
	}
	total, a := decimal(p.TotalBytes)
	used, b := decimal(p.TotalInUseBytes)
	return a && b && p.Reason == "" && p.Count != nil && *p.Count <= MaxPagefiles && used <= total && ((*p.Count == 0 && total == 0 && used == 0) || (*p.Count > 0 && total > 0))
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || !validProcessors(s.Processors) || !validInstalledMemory(s.InstalledMemory) || !validMemory(s.Memory) || !validPagefiles(s.Pagefiles) {
		return ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxBytes {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func Encode(s Snapshot) ([]byte, error) {
	if Validate(s) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(s)
}
func ValidateBinding(s Snapshot, generation, grant string, at time.Time) error {
	if Validate(s) != nil || s.GenerationID != generation || s.GrantID != grant || !s.CollectedAt.Equal(at) {
		return ErrInvalid
	}
	return nil
}
func EmptyProcessors(reason string) Processors {
	return Processors{Quality: unavailableQuality(reason), Reason: reason, Source: "Win32_Processor", Rows: []Processor{}}
}
func EmptyInstalledMemory(reason string) InstalledMemory {
	return InstalledMemory{Quality: unavailableQuality(reason), Reason: reason, Source: "GetPhysicallyInstalledSystemMemory"}
}
func EmptyMemory(reason string) Memory {
	return Memory{Quality: unavailableQuality(reason), Reason: reason, Source: "K32GetPerformanceInfo"}
}
func EmptyPagefiles(reason string) Pagefiles {
	return Pagefiles{Quality: unavailableQuality(reason), Reason: reason, Source: "EnumPageFilesW"}
}
func Empty(r Request, reason string) Snapshot {
	return Snapshot{SchemaVersion, Scope, r.Consent.GrantID, r.GenerationID, r.CollectedAt, EmptyProcessors(reason), EmptyInstalledMemory(reason), EmptyMemory(reason), EmptyPagefiles(reason)}
}
func FitBudget(s Snapshot, budget int) (Snapshot, error) {
	b, e := Encode(s)
	if e != nil {
		return Snapshot{}, e
	}
	if len(b) > budget {
		return Snapshot{}, ErrBounds
	}
	return s, nil
}
