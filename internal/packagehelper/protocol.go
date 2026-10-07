// Package packagehelper is the default-off, root-local selected APT broker,
// independent runner and mandatory pre-dpkg guard. Runtime never initializes state.
package packagehelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/nativeapt"

	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
)

const (
	RequestVersion        = "tracebolt.package-helper-request.v1"
	ResponseVersion       = "tracebolt.package-helper-response.v1"
	SnapshotVersion       = "tracebolt.package-helper-snapshot.v1"
	CapabilitiesVersion   = "tracebolt.package-helper-capabilities.v1"
	SubmitOperation       = "submit"
	StatusOperation       = "status"
	CapabilitiesOperation = "capabilities"
	MaxRequestBytes       = 264 << 10
	MaxResponseBytes      = 1 << 20
	SocketPath            = "/run/tracebolt-package-helper/package.sock"
)

var (
	ErrRejected    = errors.New("package_helper_rejected")
	ErrUnavailable = errors.New("package_helper_unavailable")
	ErrConflict    = errors.New("package_helper_conflict")
	ErrUncertain   = errors.New("package_helper_uncertain")
)

type Request struct {
	Version   string `json:"version"`
	Operation string `json:"operation"`
	Envelope  []byte `json:"envelope,omitempty"`
	JobID     string `json:"jobId,omitempty"`
}
type Snapshot struct {
	Version                   string                 `json:"version"`
	JobID                     string                 `json:"jobId"`
	Sequence                  uint64                 `json:"sequence,string"`
	PreparationEnvelopeDigest string                 `json:"preparationEnvelopeDigest"`
	ExecutionEnvelopeDigest   string                 `json:"executionEnvelopeDigest"`
	State                     string                 `json:"state"`
	Preview                   *packageupdate.Preview `json:"preview,omitempty"`
	Result                    *packageupdate.Result  `json:"result,omitempty"`
	Results                   []packageupdate.Result `json:"results"`
	UpdatedAt                 int64                  `json:"updatedAt"`
}
type Capabilities struct {
	Enabled              bool                      `json:"enabled"`
	HTTPTestAcknowledged bool                      `json:"httpTestAcknowledged"`
	Version              string                    `json:"version"`
	ManagerID            string                    `json:"managerId"`
	EndpointID           string                    `json:"endpointId"`
	IncarnationDigest    string                    `json:"incarnationDigest"`
	KeyID                string                    `json:"keyId"`
	RootPolicyDigest     string                    `json:"rootPolicyDigest"`
	TransportProfile     string                    `json:"transportProfile"`
	CapturedAt           int64                     `json:"capturedAt"`
	Allowed              []packagepermit.Selection `json:"allowed"`
}
type Response struct {
	Version      string        `json:"version"`
	Snapshot     *Snapshot     `json:"snapshot,omitempty"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	Error        string        `json:"error,omitempty"`
}

func canonical(raw []byte, v any) bool {
	b, e := json.Marshal(v)
	return e == nil && bytes.Equal(raw, b)
}
func validateRequest(r Request) error {
	if r.Version != RequestVersion {
		return ErrRejected
	}
	switch r.Operation {
	case CapabilitiesOperation:
		if len(r.Envelope) != 0 || r.JobID != "" {
			return ErrRejected
		}
	case SubmitOperation:
		if r.JobID != "" {
			return ErrRejected
		}
		if _, _, e := packagepermit.Decode(context.Background(), r.Envelope); e != nil {
			return ErrRejected
		}
	case StatusOperation:
		if len(r.Envelope) != 0 || !enrollmentcrypto.ValidID(r.JobID, "update_") {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	return nil
}
func frame(b []byte) []byte {
	out := make([]byte, 8, 8+len(b))
	copy(out, "TBP1")
	binary.BigEndian.PutUint32(out[4:], uint32(len(b)))
	return append(out, b...)
}
func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [8]byte
	if _, e := io.ReadFull(r, h[:]); e != nil || string(h[:4]) != "TBP1" {
		return nil, ErrRejected
	}
	n := binary.BigEndian.Uint32(h[4:])
	if n == 0 || n > uint32(max) {
		return nil, ErrRejected
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, ErrRejected
	}
	return b, nil
}
func EncodeRequest(r Request) ([]byte, error) {
	if e := validateRequest(r); e != nil {
		return nil, e
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxRequestBytes {
		return nil, ErrRejected
	}
	return frame(b), nil
}
func readRequest(r io.Reader) (Request, error) {
	b, e := readFrame(r, MaxRequestBytes)
	if e != nil {
		return Request{}, e
	}
	var q Request
	if json.Unmarshal(b, &q) != nil || !canonical(b, q) || validateRequest(q) != nil {
		return Request{}, ErrRejected
	}
	return q, nil
}
func ValidateCapabilities(c Capabilities) error {
	if c.Version != CapabilitiesVersion || !enrollmentcrypto.ValidID(c.ManagerID, "manager_") || !enrollmentcrypto.ValidID(c.EndpointID, "agent_") || c.CapturedAt <= 0 || len(c.Allowed) == 0 || len(c.Allowed) > 32 {
		return ErrRejected
	}
	for _, d := range []string{c.IncarnationDigest, c.KeyID, c.RootPolicyDigest} {
		if !actionpermit.ValidDigest(d) {
			return ErrRejected
		}
	}
	if (c.TransportProfile != "production-tls" && c.TransportProfile != "disposable-http-test") || c.HTTPTestAcknowledged != (c.TransportProfile == "disposable-http-test") {
		return ErrRejected
	}
	allowed := make([]nativeapt.Selection, len(c.Allowed))
	for i, s := range c.Allowed {
		allowed[i] = nativeapt.Selection{Name: s.Name, Architecture: s.Architecture}
	}
	if _, e := nativeapt.SelectionBytes(allowed); e != nil {
		return ErrRejected
	}
	return nil
}
func ValidateSnapshot(s Snapshot) error {
	if s.Version != SnapshotVersion || !enrollmentcrypto.ValidID(s.JobID, "update_") || s.Sequence == 0 || !actionpermit.ValidDigest(s.PreparationEnvelopeDigest) || s.UpdatedAt <= 0 || s.Results == nil || len(s.Results) > 8 {
		return ErrRejected
	}
	if s.ExecutionEnvelopeDigest != "" && !actionpermit.ValidDigest(s.ExecutionEnvelopeDigest) {
		return ErrRejected
	}
	switch s.State {
	case packageupdate.Preparing, packageupdate.PreviewReady, packageupdate.PreparationFailed, packageupdate.DeliveryUnknown, packageupdate.Applying, packageupdate.Verifying, packageupdate.Succeeded, packageupdate.NeedsIntervention:
	default:
		return ErrRejected
	}
	if len(s.Results) == 0 {
		if s.Result != nil {
			return ErrRejected
		}
	} else {
		if s.Result == nil {
			return ErrRejected
		}
		a, _ := json.Marshal(s.Results[len(s.Results)-1])
		b, _ := json.Marshal(s.Result)
		if !bytes.Equal(a, b) {
			return ErrRejected
		}
	}
	if s.Preview != nil {
		p := s.Preview
		if p.RequestID != s.JobID {
			return ErrRejected
		}
		request := packageupdate.PrepareRequest{RequestID: s.JobID, Packages: make([]packageupdate.Selection, len(p.Plan.Packages))}
		for i, u := range p.Plan.Packages {
			request.Packages[i] = packageupdate.Selection{Name: u.Name, Architecture: u.Architecture}
		}
		checked, e := packageupdate.DescribePreview(context.Background(), p.Binding, request, p.ActorID, p.Plan, p.Sources)
		if e != nil || !sameJSON(checked, p) {
			return ErrRejected
		}
		if s.UpdatedAt < p.Plan.CreatedAt {
			return ErrRejected
		}
	}
	switch s.State {
	case packageupdate.Preparing, packageupdate.PreparationFailed:
		if s.Preview != nil || s.ExecutionEnvelopeDigest != "" || len(s.Results) != 0 {
			return ErrRejected
		}
	case packageupdate.PreviewReady:
		if s.Preview == nil || s.ExecutionEnvelopeDigest != "" || len(s.Results) != 0 {
			return ErrRejected
		}
	case packageupdate.DeliveryUnknown:
		if s.Preview == nil || s.ExecutionEnvelopeDigest == "" || len(s.Results) != 0 {
			return ErrRejected
		}
	case packageupdate.NeedsIntervention:
		if s.ExecutionEnvelopeDigest == "" {
			if len(s.Results) != 0 || s.Result != nil {
				return ErrRejected
			}
		} else if s.Preview == nil || len(s.Results) == 0 || s.Results[len(s.Results)-1].Phase != s.State {
			return ErrRejected
		}
	default:
		if s.Preview == nil || s.ExecutionEnvelopeDigest == "" || len(s.Results) == 0 || s.Results[len(s.Results)-1].Phase != s.State {
			return ErrRejected
		}
	}
	phase := packageupdate.DeliveryUnknown
	at := int64(0)
	if s.Preview != nil {
		at = s.Preview.Plan.CreatedAt
	}
	for i, r := range s.Results {
		step := phase == packageupdate.DeliveryUnknown && (r.Phase == packageupdate.Applying || r.Phase == packageupdate.NeedsIntervention) || phase == packageupdate.Applying && (r.Phase == packageupdate.Verifying || r.Phase == packageupdate.NeedsIntervention) || phase == packageupdate.Verifying && (r.Phase == packageupdate.Succeeded || r.Phase == packageupdate.NeedsIntervention)
		if !step || r.Sequence != uint64(i+1) || r.ObservedAt < at || r.ObservedAt > s.UpdatedAt || r.Reboot.ObservedAt != r.ObservedAt || r.Reboot.Source != "native" || (r.Reboot.State != "unknown" && r.Reboot.State != "required" && r.Reboot.State != "not_reported") || (r.DpkgState != "unknown" && r.DpkgState != "clean") || len(r.Packages) != len(s.Preview.Plan.Packages) {
			return ErrRejected
		}
		if (r.Phase == packageupdate.Applying || r.Phase == packageupdate.Verifying) && (r.Reason != "native_running" || r.DpkgState != "unknown" || r.Reboot.State != "unknown") {
			return ErrRejected
		}
		if r.Phase == packageupdate.Succeeded && (r.Reason != "native_verified" || r.DpkgState != "clean") {
			return ErrRejected
		}
		if r.Phase == packageupdate.NeedsIntervention && r.Reason != "runner_state_unknown" && r.Reason != "verification_mismatch" {
			return ErrRejected
		}
		for j, v := range r.Packages {
			u := s.Preview.Plan.Packages[j]
			if v.Name != u.Name || v.Architecture != u.Architecture || v.ExpectedVersion != u.To.Version {
				return ErrRejected
			}
			switch v.Outcome {
			case "verified":
				if v.ObservedVersion == nil || *v.ObservedVersion != v.ExpectedVersion {
					return ErrRejected
				}
			case "mismatch":
				if v.ObservedVersion == nil || *v.ObservedVersion == "" || len(*v.ObservedVersion) > 1024 || *v.ObservedVersion == v.ExpectedVersion {
					return ErrRejected
				}
			case "unknown":
				if v.ObservedVersion != nil {
					return ErrRejected
				}
			default:
				return ErrRejected
			}
			if r.Phase == packageupdate.Succeeded && v.Outcome != "verified" {
				return ErrRejected
			}
		}
		phase = r.Phase
		at = r.ObservedAt
	}
	return nil
}
func ReadResponse(r io.Reader) (Response, error) {
	b, e := readFrame(r, MaxResponseBytes)
	if e != nil {
		return Response{}, e
	}
	var v Response
	if json.Unmarshal(b, &v) != nil || !canonical(b, v) || v.Version != ResponseVersion {
		return Response{}, ErrRejected
	}
	n := 0
	if v.Snapshot != nil {
		n++
		if ValidateSnapshot(*v.Snapshot) != nil {
			return Response{}, ErrRejected
		}
	}
	if v.Capabilities != nil {
		n++
		if ValidateCapabilities(*v.Capabilities) != nil {
			return Response{}, ErrRejected
		}
	}
	if v.Error != "" {
		n++
		switch v.Error {
		case "denied", "busy", "expired", "conflict", "unavailable":
		default:
			return Response{}, ErrRejected
		}
	}
	if n != 1 {
		return Response{}, ErrRejected
	}
	return v, nil
}
func writeResponse(w io.Writer, v Response) error {
	v.Version = ResponseVersion
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxResponseBytes {
		return ErrUnavailable
	}
	b = frame(b)
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// reserveOutcomeCapacity checks the largest supported three-phase outcome BEFORE
// execution admission. Large exact versions cannot create an unreportable update
// that fails only after mutation. Observed versions are bounded to 1024 bytes.
func reserveOutcomeCapacity(s Snapshot) error {
	if s.Preview == nil {
		return ErrRejected
	}
	now := s.Preview.Plan.CreatedAt
	rows := make([]packageupdate.PackageResult, len(s.Preview.Plan.Packages))
	for i, u := range s.Preview.Plan.Packages {
		observed := string(bytes.Repeat([]byte("x"), 1024))
		if observed == u.To.Version {
			observed = string(bytes.Repeat([]byte("y"), 1024))
		}
		rows[i] = packageupdate.PackageResult{Name: u.Name, Architecture: u.Architecture, ExpectedVersion: u.To.Version, ObservedVersion: &observed, Outcome: "mismatch"}
	}
	results := make([]packageupdate.Result, 3)
	for i, phase := range []string{packageupdate.Applying, packageupdate.Verifying, packageupdate.NeedsIntervention} {
		r := packageupdate.Result{Sequence: uint64(i + 1), Phase: phase, ObservedAt: now, Reboot: packageupdate.RebootEvidence{State: "unknown", Source: "native", ObservedAt: now}, DpkgState: "unknown", Reason: "native_running"}
		r.Packages = make([]packageupdate.PackageResult, len(rows))
		copy(r.Packages, rows)
		if i < 2 {
			for j := range r.Packages {
				r.Packages[j].ObservedVersion = nil
				r.Packages[j].Outcome = "unknown"
			}
		} else {
			r.Reason = "verification_mismatch"
			r.DpkgState = "clean"
		}
		raw, e := json.Marshal(r)
		if e != nil || len(raw) > 256<<10 {
			return ErrRejected
		}
		results[i] = r
	}
	s.ExecutionEnvelopeDigest = actionpermit.Digest(nil)
	s.State = packageupdate.NeedsIntervention
	s.Results = results
	s.Result = &s.Results[2]
	s.UpdatedAt = now
	if ValidateSnapshot(s) != nil {
		return ErrRejected
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxResponseBytes-1024 {
		return ErrRejected
	}
	return nil
}
