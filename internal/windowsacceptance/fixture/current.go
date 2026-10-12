package fixture

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowssetup"
)

// StartCurrentReadAdmin explicitly selects the fresh CURRENT21 TLS-only peer.
// This disposable peer exercises initial renewable enrollment, not renewal
// cutover, Linux persistence, native providers, grant creation or host setup.
func StartCurrentReadAdmin(ctx context.Context) (*Fixture, error) {
	return startMode(ctx, profile.InventoryTLS(), false, true)
}

// CurrentQualityCounts contains only finite protocol labels, never source text.
// Other preserves unknown quality counts without inventing a success result.
type CurrentQualityCounts struct {
	Observed    uint32 `json:"observed"`
	Healthy     uint32 `json:"healthy"`
	Partial     uint32 `json:"partial"`
	Denied      uint32 `json:"denied"`
	Unavailable uint32 `json:"unavailable"`
	Unknown     uint32 `json:"unknown"`
	Unsupported uint32 `json:"unsupported"`
	FirstSample uint32 `json:"firstSample"`
	Reset       uint32 `json:"reset"`
	Other       uint32 `json:"other"`
}

type CurrentSourceObservation struct {
	Scope           string               `json:"scope"`
	Kind            string               `json:"kind"` // ordinary, independent, or grant_only
	Frames          uint64               `json:"frames"`
	Samples         uint64               `json:"samples"` // terminal observations, including explicit failures
	LastSequence    uint64               `json:"lastSequence"`
	LastFrameSHA256 string               `json:"lastFrameSha256"`
	Status          string               `json:"status"` // not_run, observed, scope, pending, complete, source_failed
	Reason          string               `json:"reason"` // finite independent-capture failure reason only
	Rows            uint32               `json:"rowCount"`
	CompleteFields  uint32               `json:"completeFields"`
	TruncatedFields uint32               `json:"truncatedFields"`
	Qualities       CurrentQualityCounts `json:"qualities"`
}

type CurrentObservation struct {
	SchemaVersion               string                       `json:"schemaVersion"`
	SetupContract               string                       `json:"setupContract"`
	RenewalPolicy               string                       `json:"renewalPolicy"`
	InitialCredentialGeneration uint64                       `json:"initialCredentialGeneration"`
	AcceptedFrames              uint64                       `json:"acceptedFrames"` // ordinary frames only
	LastSequence                uint64                       `json:"lastSequence"`
	V16Frames                   uint64                       `json:"v16Frames"`
	LastFrameSHA256             string                       `json:"lastFrameSha256"`
	Sources                     [21]CurrentSourceObservation `json:"sources"`
	FullAcceptance              bool                         `json:"fullAcceptance"`
	NativeProviderProof         bool                         `json:"nativeProviderProof"`
	RenewalCycleProved          bool                         `json:"renewalCycleProved"`
}

func ZeroCurrentObservation() CurrentObservation {
	o := CurrentObservation{SchemaVersion: "tracebolt.windows-current-fixture-observation.v1", SetupContract: windowssetup.ReadAdminContractV10, RenewalPolicy: enrollmentcrypto.RenewalPolicySameKey}
	for i, scope := range lanclient.WindowsReadAdminScopesV14() {
		kind := "ordinary"
		switch scope {
		case "windows-complete-services-v1", "windows-complete-machine-software-v1", "windows-complete-processes-v1", "windows-network-context-v1":
			kind = "independent"
		case "windows-machine-software-history-v1", "windows-application-system-event-history-v1":
			kind = "grant_only"
		}
		o.Sources[i] = CurrentSourceObservation{Scope: scope, Kind: kind, Status: "not_run"}
	}
	return o
}

func (o CurrentObservation) Validate() error {
	z := ZeroCurrentObservation()
	if o.SchemaVersion != z.SchemaVersion || o.SetupContract != z.SetupContract || o.RenewalPolicy != z.RenewalPolicy || o.InitialCredentialGeneration > 1 || o.FullAcceptance || o.NativeProviderProof || o.RenewalCycleProved || o.AcceptedFrames > MaxFrames || o.V16Frames > o.AcceptedFrames || o.LastSequence > 1<<53-1 || o.AcceptedFrames > 0 && o.InitialCredentialGeneration != 1 || (o.AcceptedFrames == 0) != (o.LastSequence == 0) || !optionalHash(o.LastFrameSHA256, o.AcceptedFrames) {
		return ErrFixture
	}
	for i, s := range o.Sources {
		if s.Frames == 0 {
			if s != z.Sources[i] {
				return ErrFixture
			}
			continue
		}
		if o.InitialCredentialGeneration != 1 || s.LastSequence == 0 || s.Status == "not_run" || s.Kind == "grant_only" {
			return ErrFixture
		}
		if s.Kind == "ordinary" && (s.Frames != s.Samples || s.Frames > o.AcceptedFrames || s.LastSequence > o.LastSequence) {
			return ErrFixture
		}
		if s.Kind == "independent" && s.Samples >= s.Frames {
			return ErrFixture
		}
		if s.Kind == "independent" && (s.Status == "scope" && (s.Samples != 0 || s.Frames != 1) || s.Status == "pending" && s.Frames < 2 || s.Status == "complete" && s.Samples == 0) {
			return ErrFixture
		}
		if s.Scope != z.Sources[i].Scope || s.Kind != z.Sources[i].Kind || s.Frames > MaxRequests || s.Samples > s.Frames || s.LastSequence > 1<<53-1 || s.Rows > 32768 || s.CompleteFields > 100000 || s.TruncatedFields > 100000 || !optionalHash(s.LastFrameSHA256, s.Frames) {
			return ErrFixture
		}
		for _, v := range []uint32{s.Qualities.Observed, s.Qualities.Healthy, s.Qualities.Partial, s.Qualities.Denied, s.Qualities.Unavailable, s.Qualities.Unknown, s.Qualities.Unsupported, s.Qualities.FirstSample, s.Qualities.Reset, s.Qualities.Other} {
			if v > 100000 {
				return ErrFixture
			}
		}
		switch s.Status {
		case "not_run":
			if s.Frames != 0 || s.Samples != 0 || s.LastSequence != 0 || s.Rows != 0 || s.Qualities != (CurrentQualityCounts{}) {
				return ErrFixture
			}
		case "observed":
			if s.Kind != "ordinary" || s.Samples == 0 {
				return ErrFixture
			}
		case "scope", "pending", "complete", "source_failed":
			if s.Kind != "independent" || s.Frames == 0 {
				return ErrFixture
			}
		default:
			return ErrFixture
		}
		if s.Kind == "grant_only" && s.Status != "not_run" {
			return ErrFixture
		}
		if (s.Status == "scope" || s.Status == "pending") && (s.Rows != 0 || s.CompleteFields != 0 || s.TruncatedFields != 0 || s.Qualities != (CurrentQualityCounts{})) {
			return ErrFixture
		}
		if s.Status == "source_failed" {
			if !currentFailureReason(s.Reason) || s.Samples == 0 {
				return ErrFixture
			}
		} else if s.Reason != "" {
			return ErrFixture
		}
		if s.Status == "complete" && s.Samples == 0 {
			return ErrFixture
		}
	}
	return nil
}
func optionalHash(h string, n uint64) bool {
	return n == 0 && h == "" || n > 0 && enrollmentcrypto.ValidHash(h)
}
func currentFailureReason(s string) bool {
	switch s {
	case "access_denied", "unavailable", "unsupported", "source_changed", "malformed_source", "resource_limit", "deadline", "canceled":
		return true
	}
	return false
}

// Ready is transport progress only. Denied, empty, unsupported, bounded or
// failed providers remain visible. Grant-only/history domains require separate
// setup receipts and are never promoted to observed history by this peer.
func (o CurrentObservation) Ready() bool {
	if o.Validate() != nil || o.InitialCredentialGeneration != 1 || o.V16Frames == 0 {
		return false
	}
	for _, s := range o.Sources {
		if s.Kind != "grant_only" && s.Samples == 0 {
			return false
		}
		if s.Kind == "independent" && s.Status != "complete" && s.Status != "source_failed" {
			return false
		}
	}
	return true
}
func (f *Fixture) CurrentEvidence() CurrentObservation {
	if f == nil || f.state == nil {
		return ZeroCurrentObservation()
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.currentObservation
	if s.current && s.issued.Valid() {
		v, e := s.snapshot()
		if e == nil && v.State == enrollmentstate.Activated {
			o.InitialCredentialGeneration = 1
		}
	}
	return o
}
func (o *CurrentObservation) source(scope string) *CurrentSourceObservation {
	for i := range o.Sources {
		if o.Sources[i].Scope == scope {
			return &o.Sources[i]
		}
	}
	return nil
}

// currentParts is built only from a successfully production-validated frame.
// Collection floors are independent even when two providers happen to share a
// timestamp. The generic projection below never saves the source object.
func currentParts(f lanstore.Frame) map[string]any {
	out := map[string]any{}
	if f.WindowsInventory != nil {
		out["windows-inventory-v1"] = f.WindowsInventory
	}
	if f.WindowsEvents != nil {
		out["windows-application-system-event-headers-v1"] = f.WindowsEvents
	}
	if f.WindowsVolumes != nil {
		out["windows-visible-volumes-v1"] = f.WindowsVolumes
	}
	if f.WindowsProcessMetrics != nil {
		out["windows-process-metrics-v1"] = f.WindowsProcessMetrics
	}
	if f.WindowsNetwork != nil {
		out["windows-network-endpoints-v1"] = f.WindowsNetwork
	}
	if f.WindowsServiceStartup != nil {
		out["windows-service-startup-v1"] = f.WindowsServiceStartup
	}
	if f.WindowsAdapterContext != nil {
		out["windows-adapter-context-v1"] = f.WindowsAdapterContext
	}
	if f.WindowsPatchContext != nil {
		out["windows-patch-context-v1"] = f.WindowsPatchContext
	}
	if f.WindowsSecurityPosture != nil {
		out["windows-security-posture-v1"] = f.WindowsSecurityPosture
	}
	if f.WindowsSessionContext != nil {
		out["windows-session-context-v1"] = f.WindowsSessionContext
	}
	if f.WindowsHardwareContext != nil {
		out["windows-hardware-context-v1"] = f.WindowsHardwareContext
	}
	if f.WindowsStorageContext != nil {
		out["windows-storage-context-v1"] = f.WindowsStorageContext
	}
	if f.WindowsSecurityCoverage != nil {
		out["windows-security-coverage-v1"] = f.WindowsSecurityCoverage
	}
	if f.WindowsResourceContext != nil {
		out["windows-resource-context-v1"] = f.WindowsResourceContext
	}
	if f.WindowsStorageIO != nil {
		out["windows-storage-io-v1"] = f.WindowsStorageIO
	}
	return out
}
func (s *state) currentShape(f lanstore.Frame) bool {
	return s.selection == profile.InventoryTLS() && f.WindowsInventory != nil && f.WindowsUpdates == nil && f.Operational == nil && f.Packages == nil
}
func captureTime(v any) time.Time {
	raw, _ := json.Marshal(v)
	defer clear(raw)
	var c struct {
		CollectedAt time.Time `json:"collectedAt"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.CollectedAt
}
func (s *state) currentAdvance(f lanstore.Frame) bool {
	for scope, part := range currentParts(f) {
		at := captureTime(part)
		if at.IsZero() || !s.currentFloors[scope].IsZero() && !at.After(s.currentFloors[scope]) {
			return false
		}
	}
	return true
}
func (s *state) observeCurrent(f lanstore.Frame, raw []byte) {
	o := &s.currentObservation
	o.AcceptedFrames++
	o.LastSequence = f.Sequence
	o.LastFrameSHA256 = digest(raw)
	if f.SchemaVersion == lanstore.FrameWindowsStorageIOVersion {
		o.V16Frames++
	}
	for scope, part := range currentParts(f) {
		dst := o.source(scope)
		frames, samples := dst.Frames+1, dst.Samples+1
		*dst = CurrentSourceObservation{Scope: scope, Kind: "ordinary", Frames: frames, Samples: samples, LastSequence: f.Sequence, LastFrameSHA256: o.LastFrameSHA256, Status: "observed"}
		projectCurrent(part, dst)
		if scope == "windows-inventory-v1" {
			for _, q := range []string{f.Observation.Observation.CPU.Quality, f.Observation.Observation.Memory.Quality, f.Observation.Observation.Disk.Quality} {
				addCurrentQuality(&dst.Qualities, q)
			}
		}
		s.currentFloors[scope] = captureTime(part)
	}
}
func projectCurrent(v any, dst *CurrentSourceObservation) {
	raw, _ := json.Marshal(v)
	defer clear(raw)
	var value any
	_ = json.Unmarshal(raw, &value)
	projectValue(value, dst)
}
func projectValue(value any, dst *CurrentSourceObservation) {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			projectValue(child, dst)
		}
	case map[string]any:
		for k, child := range v {
			if k == "rows" {
				if a, ok := child.([]any); ok {
					dst.Rows += uint32(len(a))
				}
			}
			if b, ok := child.(bool); ok && b {
				if k == "complete" {
					dst.CompleteFields++
				}
				if k == "truncated" {
					dst.TruncatedFields++
				}
			}
			if k == "quality" || strings.HasSuffix(k, "Quality") {
				if q, ok := child.(string); ok {
					addCurrentQuality(&dst.Qualities, q)
				}
			}
			projectValue(child, dst)
		}
	}
}
func addCurrentQuality(c *CurrentQualityCounts, q string) {
	switch q {
	case "observed":
		c.Observed++
	case "healthy":
		c.Healthy++
	case "partial":
		c.Partial++
	case "denied":
		c.Denied++
	case "unavailable":
		c.Unavailable++
	case "unknown":
		c.Unknown++
	case "unsupported":
		c.Unsupported++
	case "first-sample":
		c.FirstSample++
	case "reset":
		c.Reset++
	default:
		c.Other++
	}
}
