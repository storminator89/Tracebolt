// Package packageupdate defines distinct simulation and native selected-package
// workflow records. Native records bind externally signed package permits to
// durable claims and exact evidence; this package never executes host commands.
package packageupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
)

const (
	Version           = "tracebolt.package-update-record.v3"
	PreviewVersion    = "tracebolt.package-update-preview.v1"
	ViewVersion       = "tracebolt.package-update-workflow.v2"
	MaxJobs           = 8 // No pruning/reinitialization: a future durable floor is mandatory.
	MaxRecordBytes    = 2 << 20
	MaxPrepareBytes   = 16 << 10
	ConffilePolicy    = "preserve-modified-dpkg-conffiles"
	Preparing         = "preparing"
	PreviewReady      = "preview_ready"
	Approved          = "approved"
	DeliveryUnknown   = "delivery_unknown"
	Expired           = "expired"
	Revoked           = "revoked"
	PreparationFailed = "preparation_failed"
	Applying          = "applying"
	Verifying         = "verifying"
	Succeeded         = "succeeded"
	NeedsIntervention = "needs_intervention"
	MaxResults        = 8
)

var (
	ErrInvalid     = errors.New("package_update_invalid")
	ErrUnavailable = errors.New("package_update_unavailable")
	ErrConflict    = errors.New("package_update_conflict")
	ErrExpired     = errors.New("package_update_expired")
	ErrUncertain   = errors.New("package_update_persistence_uncertain")
	ErrCapacity    = errors.New("package_update_capacity")
	ErrNotFound    = errors.New("package_update_not_found")
	namePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)
	archPattern    = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Selection is user intent only. It cannot carry repository URLs, plan evidence,
// archive paths, commands or execution options. The future adapter resolves it.
type Selection struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
}
type PrepareRequest struct {
	RequestID string      `json:"requestId"`
	Packages  []Selection `json:"packages"`
}
type ApprovalRequest struct {
	RequestID     string `json:"requestId"`
	PreviewDigest string `json:"previewDigest"`
}
type Binding struct {
	ManagerID         string `json:"managerId"`
	DeviceID          string `json:"deviceId"`
	IncarnationDigest string `json:"incarnationDigest"`
	RootPolicyDigest  string `json:"rootPolicyDigest"`
	TransportProfile  string `json:"transportProfile"`
}

// Source is protected-adapter output, never caller-provided provenance. Its
// human-readable fields are committed by Preview.Digest as well as exact hashes.
type Source struct {
	IdentityDigest string `json:"identityDigest"`
	Label          string `json:"label"`
	Suite          string `json:"suite"`
	Component      string `json:"component"`
}
type Preview struct {
	Version        string           `json:"version"`
	RequestID      string           `json:"requestId"`
	ActorID        string           `json:"actorId"`
	Binding        Binding          `json:"binding"`
	Plan           packageplan.Plan `json:"plan"`
	PlanDigest     string           `json:"planDigest"`
	Sources        []Source         `json:"sources"`
	ConffilePolicy string           `json:"conffilePolicy"`
	Digest         string           `json:"digest"`
}
type Job struct {
	PreparationEnvelope  []byte         `json:"preparationEnvelope"`
	PreparationClaimedAt int64          `json:"preparationClaimedAt"`
	ExecutionEnvelope    []byte         `json:"executionEnvelope"`
	Sequence             uint64         `json:"sequence,string"`
	Request              PrepareRequest `json:"request"`
	ActorID              string         `json:"actorId"`
	CreatedAt            int64          `json:"createdAt"`
	UpdatedAt            int64          `json:"updatedAt"`
	State                string         `json:"state"`
	Preview              *Preview       `json:"preview"`
	ApprovedAt           int64          `json:"approvedAt"`
	ClaimedAt            int64          `json:"claimedAt"`
	Results              []Result       `json:"results"`
}
type Record struct {
	Mode       string  `json:"mode"`
	PublicKey  []byte  `json:"publicKey"`
	Version    string  `json:"version"`
	Binding    Binding `json:"binding"`
	Revision   uint64  `json:"revision,string"`
	ClockFloor int64   `json:"clockFloor"`
	RevokedAt  int64   `json:"revokedAt"`
	Jobs       []Job   `json:"jobs"`
}

func validTime(t int64) bool { return t > 0 && t <= 253402300799 }
func validBinding(b Binding) bool {
	return enrollmentcrypto.ValidID(b.ManagerID, "manager_") && enrollmentcrypto.ValidID(b.DeviceID, "agent_") && actionpermit.ValidDigest(b.IncarnationDigest) && actionpermit.ValidDigest(b.RootPolicyDigest) && (b.TransportProfile == "production-tls" || b.TransportProfile == "disposable-http-test")
}
func ValidatePrepare(r PrepareRequest) error {
	if !enrollmentcrypto.ValidID(r.RequestID, "update_") || len(r.Packages) == 0 || len(r.Packages) > packageplan.MaxPackages {
		return ErrInvalid
	}
	lastName, lastArch := "", ""
	for _, p := range r.Packages {
		if !namePattern.MatchString(p.Name) || len(p.Architecture) > 64 || !archPattern.MatchString(p.Architecture) || p.Architecture == "source" || p.Name < lastName || p.Name == lastName && p.Architecture <= lastArch {
			return ErrInvalid
		}
		for _, part := range strings.Split(p.Architecture, "-") {
			if part == "any" {
				return ErrInvalid
			}
		}
		lastName, lastArch = p.Name, p.Architecture
	}
	return nil
}
func previewDigest(p Preview) string {
	p.Digest = ""
	raw, _ := json.Marshal(p)
	return actionpermit.Digest(append([]byte("Tracebolt package update preview v1\x00"), raw...))
}
func safeLabel(s string) bool {
	if len(s) == 0 || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validatePreview(ctx context.Context, p Preview, r PrepareRequest, actor string, b Binding) error {
	d, e := packageplan.Digest(ctx, p.Plan)
	if e != nil || p.Version != PreviewVersion || p.RequestID != r.RequestID || p.ActorID != actor || p.Binding != b || p.PlanDigest != d || p.ConffilePolicy != ConffilePolicy || p.Digest != previewDigest(p) || p.Plan.EndpointID != b.DeviceID || p.Plan.IncarnationDigest != b.IncarnationDigest || p.Plan.RootPolicyDigest != b.RootPolicyDigest || len(p.Plan.Packages) != len(r.Packages) || len(p.Sources) == 0 || len(p.Sources) > packageplan.MaxPackages {
		return ErrInvalid
	}
	sources := map[string]bool{}
	last := ""
	for _, s := range p.Sources {
		if !actionpermit.ValidDigest(s.IdentityDigest) || s.IdentityDigest <= last || !safeLabel(s.Label) || !safeLabel(s.Suite) || !safeLabel(s.Component) {
			return ErrInvalid
		}
		sources[s.IdentityDigest] = false
		last = s.IdentityDigest
	}
	for i, u := range p.Plan.Packages {
		if u.Name != r.Packages[i].Name || u.Architecture != r.Packages[i].Architecture {
			return ErrConflict
		}
		if _, ok := sources[u.Archive.SourceIdentityDigest]; !ok {
			return ErrInvalid
		}
		sources[u.Archive.SourceIdentityDigest] = true
	}
	for _, used := range sources {
		if !used {
			return ErrInvalid
		}
	}
	return nil
}

// DescribePreview validates supplied observations only. It does NOT establish
// native authenticity. Runtime code must not call it on cached inventory rows.
func DescribePreview(ctx context.Context, b Binding, r PrepareRequest, actor string, p packageplan.Plan, sources []Source) (Preview, error) {
	if !validBinding(b) || ValidatePrepare(r) != nil || !enrollmentcrypto.ValidID(actor, "operator_") {
		return Preview{}, ErrInvalid
	}
	d, e := packageplan.Digest(ctx, p)
	if e != nil {
		return Preview{}, e
	}
	v := Preview{PreviewVersion, r.RequestID, actor, b, p, d, sources, ConffilePolicy, ""}
	v.Digest = previewDigest(v)
	if e = validatePreview(ctx, v, r, actor, b); e != nil {
		return Preview{}, e
	}
	// Defensive roundtrip: callers cannot mutate retained package/source slices.
	raw, _ := json.Marshal(v)
	var out Preview
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func Validate(ctx context.Context, r Record) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if (r.Mode != "simulation" && r.Mode != "native") || (r.Mode == "simulation" && len(r.PublicKey) != 0) || (r.Mode == "native" && !keyvalidation.Ed25519(r.PublicKey)) || r.Version != Version || !validBinding(r.Binding) || r.Revision == 0 || !validTime(r.ClockFloor) || r.Jobs == nil || len(r.Jobs) > MaxJobs || r.RevokedAt < 0 || r.RevokedAt > r.ClockFloor {
		return ErrInvalid
	}
	ids := map[string]bool{}
	for i, j := range r.Jobs {
		if j.Sequence != uint64(i+1) || ValidatePrepare(j.Request) != nil || ids[j.Request.RequestID] || !enrollmentcrypto.ValidID(j.ActorID, "operator_") || !validTime(j.CreatedAt) || j.UpdatedAt < j.CreatedAt || j.UpdatedAt > r.ClockFloor || j.ApprovedAt < 0 || j.ClaimedAt < 0 {
			return ErrInvalid
		}
		ids[j.Request.RequestID] = true
		if r.RevokedAt != 0 && (j.CreatedAt > r.RevokedAt || j.ApprovedAt > r.RevokedAt || j.ClaimedAt > r.RevokedAt || j.PreparationClaimedAt > r.RevokedAt) {
			return ErrInvalid
		}
		if j.Preview != nil {
			if validatePreview(ctx, *j.Preview, j.Request, j.ActorID, r.Binding) != nil || j.Preview.Plan.CreatedAt < j.CreatedAt || j.Preview.Plan.CreatedAt > j.UpdatedAt {
				return ErrInvalid
			}
		}
		if j.ApprovedAt != 0 && (j.Preview == nil || packageplan.CheckFresh(ctx, j.Preview.Plan, j.ApprovedAt) != nil || j.ApprovedAt < j.Preview.Plan.CreatedAt || j.ApprovedAt >= j.Preview.Plan.ExpiresAt || j.ApprovedAt > j.UpdatedAt) {
			return ErrInvalid
		}
		if j.ClaimedAt != 0 && (j.ApprovedAt == 0 || packageplan.CheckFresh(ctx, j.Preview.Plan, j.ClaimedAt) != nil || j.ClaimedAt < j.ApprovedAt || j.ClaimedAt >= j.Preview.Plan.ExpiresAt || j.ClaimedAt > j.UpdatedAt) {
			return ErrInvalid
		}
		if validateNativeJob(ctx, r, j) != nil {
			return ErrInvalid
		}
		if validateResults(j, r.Mode) != nil {
			return ErrInvalid
		}
		switch j.State {
		case Preparing:
			if j.Preview != nil || j.ApprovedAt != 0 || r.RevokedAt != 0 {
				return ErrInvalid
			}
		case PreviewReady:
			if j.Preview == nil || j.ApprovedAt != 0 || r.RevokedAt != 0 {
				return ErrInvalid
			}
		case Approved:
			if j.ApprovedAt == 0 || j.ClaimedAt != 0 || r.RevokedAt != 0 {
				return ErrInvalid
			}
		case DeliveryUnknown:
			if j.ClaimedAt == 0 || len(j.Results) != 0 {
				return ErrInvalid
			}
		case NeedsIntervention:
			if r.Mode == "native" && j.PreparationClaimedAt != 0 && j.ApprovedAt == 0 && j.ClaimedAt == 0 && len(j.Results) == 0 {
				break // Lost preparation is fenced even though no install was approved.
			}
			fallthrough
		case Applying, Verifying, Succeeded:
			if j.ClaimedAt == 0 || len(j.Results) == 0 || j.Results[len(j.Results)-1].Phase != j.State {
				return ErrInvalid
			}
		case Expired:
			if j.Preview == nil || j.ClaimedAt != 0 || j.UpdatedAt < j.Preview.Plan.ExpiresAt {
				return ErrInvalid
			}
		case Revoked:
			if r.RevokedAt == 0 || j.ClaimedAt != 0 || j.UpdatedAt < r.RevokedAt {
				return ErrInvalid
			}
		case PreparationFailed:
			if j.Preview != nil || j.ApprovedAt != 0 || j.ClaimedAt != 0 {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if i < len(r.Jobs)-1 && (!terminal(j) || r.Jobs[i+1].CreatedAt < j.UpdatedAt) {
			return ErrInvalid
		}
	}
	return nil
}
func Encode(ctx context.Context, r Record) ([]byte, error) {
	if e := Validate(ctx, r); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxRecordBytes {
		return nil, ErrCapacity
	}
	return raw, nil
}
func Decode(ctx context.Context, raw []byte) (Record, error) {
	var r Record
	if len(raw) == 0 || len(raw) > MaxRecordBytes || json.Unmarshal(raw, &r) != nil {
		return Record{}, ErrInvalid
	}
	b, e := Encode(ctx, r)
	if e != nil {
		return Record{}, e
	}
	if !bytes.Equal(raw, b) {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func New(b Binding, now int64) (Record, error) {
	r := Record{Mode: "simulation", Version: Version, Binding: b, Revision: 1, ClockFloor: now, Jobs: []Job{}}
	return r, Validate(context.Background(), r)
}
func terminal(j Job) bool {
	return j.State == Expired || j.State == Revoked || j.State == PreparationFailed || j.State == Succeeded
}

// advance clones state. Failures leave the caller's old snapshot unchanged.
func advance(ctx context.Context, r Record, now int64) (Record, error) {
	raw, e := Encode(ctx, r)
	if e != nil {
		return Record{}, e
	}
	if !validTime(now) || now < r.ClockFloor || r.Revision == ^uint64(0) {
		return Record{}, ErrInvalid
	}
	out, e := Decode(ctx, raw)
	if e != nil {
		return Record{}, e
	}
	out.ClockFloor = now
	out.Revision++
	for i := range out.Jobs {
		j := &out.Jobs[i]
		if out.Mode == "native" && j.State == Preparing && j.PreparationClaimedAt == 0 {
			p, _, e := packagepermit.Decode(ctx, j.PreparationEnvelope)
			if e != nil {
				return Record{}, ErrInvalid
			}
			if now >= p.StartDeadline {
				j.State = PreparationFailed
				j.UpdatedAt = now
			}
		}
		if (j.State == PreviewReady || j.State == Approved) && now >= j.Preview.Plan.ExpiresAt {
			j.State = Expired
			j.UpdatedAt = now
		}
	}
	return out, nil
}
func Observe(ctx context.Context, r Record, now int64) (Record, error) { return advance(ctx, r, now) }
func Prepare(ctx context.Context, r Record, req PrepareRequest, actor string, now int64) (Record, error) {
	return prepare(ctx, r, req, actor, now, nil)
}
func PrepareNative(ctx context.Context, r Record, req PrepareRequest, actor string, now int64, authority []byte) (Record, error) {
	return prepare(ctx, r, req, actor, now, authority)
}
func prepare(ctx context.Context, r Record, req PrepareRequest, actor string, now int64, authority []byte) (Record, error) {
	if ValidatePrepare(req) != nil || !enrollmentcrypto.ValidID(actor, "operator_") {
		return Record{}, ErrInvalid
	}
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	for _, j := range out.Jobs {
		if j.Request.RequestID == req.RequestID {
			a, _ := json.Marshal(req)
			b, _ := json.Marshal(j.Request)
			if j.ActorID != actor || !bytes.Equal(a, b) {
				return Record{}, ErrConflict
			}
			return out, nil
		}
	}
	// A new job follows only a terminal state already present in the committed
	// input. Persist Observe first when the previous preview has just expired.
	if len(r.Jobs) > 0 && !terminal(r.Jobs[len(r.Jobs)-1]) {
		return Record{}, ErrConflict
	}
	if out.RevokedAt != 0 {
		return Record{}, ErrUnavailable
	}
	if len(out.Jobs) >= MaxJobs {
		return Record{}, ErrCapacity
	}
	if len(out.Jobs) > 0 && !terminal(out.Jobs[len(out.Jobs)-1]) {
		return Record{}, ErrConflict
	}
	raw, _ := json.Marshal(req)
	var owned PrepareRequest
	_ = json.Unmarshal(raw, &owned)
	if (r.Mode == "native") != (len(authority) > 0) {
		return Record{}, ErrInvalid
	}
	out.Jobs = append(out.Jobs, Job{PreparationEnvelope: bytes.Clone(authority), Sequence: uint64(len(out.Jobs) + 1), Request: owned, ActorID: actor, CreatedAt: now, UpdatedAt: now, State: Preparing})
	return out, Validate(ctx, out)
}
func AttachPreview(ctx context.Context, r Record, p Preview, now int64) (Record, error) {
	return attachPreview(ctx, r, p, now, false)
}

// AttachNativePreview retains exact historical evidence after an offline interval.
// Expired evidence becomes terminal immediately and can never be approved.
func AttachNativePreview(ctx context.Context, r Record, p Preview, now int64) (Record, error) {
	if r.Mode != "native" {
		return Record{}, ErrInvalid
	}
	return attachPreview(ctx, r, p, now, true)
}
func attachPreview(ctx context.Context, r Record, p Preview, now int64, historical bool) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if out.RevokedAt != 0 || len(out.Jobs) == 0 {
		return Record{}, ErrUnavailable
	}
	j := &out.Jobs[len(out.Jobs)-1]
	if p.RequestID != j.Request.RequestID || validatePreview(ctx, p, j.Request, j.ActorID, out.Binding) != nil {
		return Record{}, ErrConflict
	}
	if j.Preview != nil {
		if j.Preview.Digest != p.Digest {
			return Record{}, ErrConflict
		}
		return out, nil
	}
	if j.State != Preparing || p.Plan.CreatedAt < j.CreatedAt || p.Plan.CreatedAt > now || (historical && j.PreparationClaimedAt == 0) || (!historical && packageplan.CheckFresh(ctx, p.Plan, now) != nil) {
		return Record{}, ErrExpired
	}
	raw, _ := json.Marshal(p)
	var owned Preview
	_ = json.Unmarshal(raw, &owned)
	j.Preview = &owned
	j.State = PreviewReady
	if historical && now >= p.Plan.ExpiresAt {
		j.State = Expired
	}
	j.UpdatedAt = now
	return out, Validate(ctx, out)
}
func Approve(ctx context.Context, r Record, req ApprovalRequest, actor string, now int64) (Record, error) {
	return approve(ctx, r, req, actor, now, nil)
}
func ApproveNative(ctx context.Context, r Record, req ApprovalRequest, actor string, now int64, authority []byte) (Record, error) {
	return approve(ctx, r, req, actor, now, authority)
}
func approve(ctx context.Context, r Record, req ApprovalRequest, actor string, now int64, authority []byte) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	for i := range out.Jobs {
		j := &out.Jobs[i]
		if j.Request.RequestID != req.RequestID {
			continue
		}
		if j.ActorID != actor || j.Preview == nil || j.Preview.Digest != req.PreviewDigest {
			return Record{}, ErrConflict
		}
		// Exact retries return original status, including expiry/revocation/uncertainty.
		if j.ApprovedAt != 0 {
			if len(authority) > 0 && !bytes.Equal(authority, j.ExecutionEnvelope) {
				return Record{}, ErrConflict
			}
			return out, nil
		}
		if out.RevokedAt != 0 {
			return Record{}, ErrUnavailable
		}
		if j.State == Expired || packageplan.CheckFresh(ctx, j.Preview.Plan, now) != nil {
			return Record{}, ErrExpired
		}
		if j.State != PreviewReady {
			return Record{}, ErrConflict
		}
		if (r.Mode == "native") != (len(authority) > 0) {
			return Record{}, ErrInvalid
		}
		j.ExecutionEnvelope = bytes.Clone(authority)
		j.ApprovedAt = now
		j.UpdatedAt = now
		j.State = Approved
		return out, Validate(ctx, out)
	}
	return Record{}, ErrConflict
}

// ClaimForFixture is the simulation-only claim model.
func ClaimForFixture(ctx context.Context, r Record, id, digest string, now int64) (Record, error) {
	if r.Mode != "simulation" {
		return Record{}, ErrInvalid
	}
	return claimExecution(ctx, r, id, digest, now)
}

// ClaimExecution consumes a native delivery before the signed envelope is returned.
// A lost response is status-only; no caller may dispatch a second time.
func ClaimExecution(ctx context.Context, r Record, id, digest string, now int64) (Record, error) {
	if r.Mode != "native" {
		return Record{}, ErrInvalid
	}
	return claimExecution(ctx, r, id, digest, now)
}
func claimExecution(ctx context.Context, r Record, id, digest string, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if len(out.Jobs) == 0 {
		return Record{}, ErrConflict
	}
	j := &out.Jobs[len(out.Jobs)-1]
	if j.Request.RequestID != id || j.Preview == nil || j.Preview.Digest != digest {
		return Record{}, ErrConflict
	}
	if j.ClaimedAt != 0 {
		return out, nil
	}
	if out.RevokedAt != 0 {
		return Record{}, ErrUnavailable
	}
	if j.State != Approved || packageplan.CheckFresh(ctx, j.Preview.Plan, now) != nil {
		return Record{}, ErrExpired
	}
	if out.Mode == "native" {
		if _, e := packagepermit.Verify(ctx, j.ExecutionEnvelope, nativePins(out, *j), now); e != nil {
			return Record{}, ErrExpired
		}
	}
	j.ClaimedAt = now
	j.UpdatedAt = now
	j.State = DeliveryUnknown
	return out, Validate(ctx, out)
}
func Revoke(ctx context.Context, r Record, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if out.RevokedAt != 0 {
		return out, nil
	}
	out.RevokedAt = now
	for i := range out.Jobs {
		j := &out.Jobs[i]
		if !terminal(*j) && j.ClaimedAt == 0 {
			j.State = Revoked
			j.UpdatedAt = now
		}
	}
	return out, Validate(ctx, out)
}

// NewNative initializes a distinct explicit local manager scope; it is never
// inferred from an existing simulation record, inventory grant or legacy store.
func NewNative(b Binding, key ed25519.PublicKey, now int64) (Record, error) {
	r := Record{Mode: "native", PublicKey: bytes.Clone(key), Version: Version, Binding: b, Revision: 1, ClockFloor: now, Jobs: []Job{}}
	return r, Validate(context.Background(), r)
}
func nativePins(r Record, j Job) packagepermit.Pins {
	allowed := make([]packagepermit.Selection, len(j.Request.Packages))
	for i, s := range j.Request.Packages {
		allowed[i] = packagepermit.Selection{Name: s.Name, Architecture: s.Architecture}
	}
	return packagepermit.Pins{ManagerID: r.Binding.ManagerID, EndpointID: r.Binding.DeviceID, IncarnationDigest: r.Binding.IncarnationDigest, RootPolicyDigest: r.Binding.RootPolicyDigest, PublicKey: r.PublicKey, Allowed: allowed}
}
func validateNativeJob(ctx context.Context, r Record, j Job) error {
	if r.Mode == "simulation" {
		if len(j.PreparationEnvelope) != 0 || j.PreparationClaimedAt != 0 || len(j.ExecutionEnvelope) != 0 {
			return ErrInvalid
		}
		return nil
	}
	p, e := packagepermit.CheckSignature(ctx, j.PreparationEnvelope, nativePins(r, j))
	if e != nil || p.Action != packagepermit.Prepare || p.JobID != j.Request.RequestID || p.Sequence != j.Sequence || p.ActorID != j.ActorID || p.IssuedAt != j.CreatedAt || !equalJSON(p.Selection, nativePins(r, j).Allowed) {
		return ErrInvalid
	}
	if j.PreparationClaimedAt != 0 && (!validTime(j.PreparationClaimedAt) || j.PreparationClaimedAt < p.IssuedAt || j.PreparationClaimedAt >= p.StartDeadline || j.PreparationClaimedAt > j.UpdatedAt) {
		return ErrInvalid
	}
	if j.Preview != nil && j.PreparationClaimedAt == 0 {
		return ErrInvalid
	}
	if j.ApprovedAt == 0 {
		if len(j.ExecutionEnvelope) != 0 {
			return ErrInvalid
		}
		return nil
	}
	q, e := packagepermit.CheckSignature(ctx, j.ExecutionEnvelope, nativePins(r, j))
	if e != nil || q.Action != packagepermit.Execute || q.JobID != j.Request.RequestID || q.Sequence != j.Sequence || q.ActorID != j.ActorID || q.IssuedAt != j.ApprovedAt || q.PreviewDigest != j.Preview.Digest || q.PlanDigest != j.Preview.PlanDigest || !equalJSON(q.Plan, &j.Preview.Plan) || !equalJSON(q.Selection, nativePins(r, j).Allowed) || (j.ClaimedAt != 0 && (j.ClaimedAt < q.NotBefore || j.ClaimedAt >= q.StartDeadline)) {
		return ErrInvalid
	}
	return nil
}
func ClaimPreparation(ctx context.Context, r Record, id, digest string, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if r.Mode != "native" || out.RevokedAt != 0 || len(out.Jobs) == 0 {
		return Record{}, ErrUnavailable
	}
	j := &out.Jobs[len(out.Jobs)-1]
	if j.Request.RequestID != id || actionpermit.Digest(j.PreparationEnvelope) != digest {
		return Record{}, ErrConflict
	}
	if j.PreparationClaimedAt != 0 {
		return out, nil
	}
	if j.State != Preparing {
		return Record{}, ErrConflict
	}
	if _, e = packagepermit.Verify(ctx, j.PreparationEnvelope, nativePins(out, *j), now); e != nil {
		return Record{}, ErrExpired
	}
	j.PreparationClaimedAt = now
	j.UpdatedAt = now
	return out, Validate(ctx, out)
}
