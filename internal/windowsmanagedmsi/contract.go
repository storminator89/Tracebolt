// Package windowsmanagedmsi is the fresh, separately consented managed MSI
// delivery/install domain. No prepared-v1 consent, signature, key or ledger is
// accepted here. Selection/readiness are closed value types, not authority.
package windowsmanagedmsi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	fence "localrmm/internal/windowsmutationfence"
	prepared "localrmm/internal/windowssoftwarejob"
)

const (
	Version                 = "tracebolt.windows-managed-msi.v1"
	GrantVersion            = "tracebolt.windows-managed-msi-grant.v1"
	CoordinatedGrantVersion = "tracebolt.windows-managed-msi-grant.v2"
	MaxChunkBytes           = 32 << 10
	MaxFrameBytes           = 64 << 10
	MaxArtifactBytes        = 128 << 20
	MaxChunks               = MaxArtifactBytes / MaxChunkBytes
	MaxRecordBytes          = 256 << 10
	DeliveryLifetime        = 24 * time.Hour
	PreviewLifetime         = 60 * time.Second
	MaintenanceLifetime     = 10 * time.Minute
	DeliveryDisclosure      = "Allow one exact centrally selected x64 machine MSI to be delivered and imported in the background by a separate deployment service. Upload and delivery do not approve package terms or installation. No arbitrary path, URL, EXE, shell, transform, patch, repair, upgrade, uninstall or caller-supplied MSI property is supported."
	InstallDisclosure       = "Allow one separately reviewed and explicitly approved install of the delivered exact MSI during a bounded maintenance window. Every package requires its own terms, custom-action and native-acceptance review. A hash proves bytes, not safety or offline behavior. No automatic retry or reboot is provided."
	ServiceDisclosure       = "The dedicated deployment service runs as LocalSystem with an unrestricted elevated token and extensive local authority, including machine-account network access. MSI custom actions can run arbitrary code, contact the network, change services and disrupt applications. This service and installer are not sandboxed. Stopping the service does not prove installation stopped or rolled back."
)

var (
	ErrInvalid     = errors.New("windows_managed_msi_invalid")
	ErrAuthority   = errors.New("windows_managed_msi_authority")
	ErrIntegrity   = errors.New("windows_managed_msi_integrity")
	ErrConflict    = errors.New("windows_managed_msi_conflict")
	ErrExpired     = errors.New("windows_managed_msi_expired")
	ErrUncertain   = errors.New("windows_managed_msi_intervention_required")
	ErrUnavailable = errors.New("windows_managed_msi_unavailable")
	ErrConsumed    = errors.New("windows_managed_msi_consumed")
)

type Selection = prepared.Selection
type Readiness = prepared.Readiness
type NativeResult = prepared.NativeResult
type Result = prepared.Result
type Fact = prepared.Fact

const (
	Yes     = prepared.Yes
	No      = prepared.No
	Unknown = prepared.Unknown
)

func ValidSelection(s Selection) bool { return prepared.ValidSelection(s) }
func Digest(b []byte) string          { return actionpermit.Digest(b) }
func ValidDigest(s string) bool       { return actionpermit.ValidDigest(s) }
func ValidTime(n int64) bool          { return n > 0 && n <= 253402300799 }
func ValidTransferID(s string) bool   { return enrollmentcrypto.ValidID(s, "transfer_") }

type Binding struct {
	ManagerID         string `json:"managerId"`
	DeviceID          string `json:"deviceId"`
	IncarnationDigest string `json:"incarnationDigest"`
	ExecutorID        string `json:"executorId"`
	ExecutorKeyID     string `json:"executorKeyId"`
	KeyID             string `json:"keyId"`
	DeliveryGrantID   string `json:"deliveryGrantId"`
	InstallGrantID    string `json:"installGrantId"`
}

func (b Binding) Validate() error {
	if !enrollmentcrypto.ValidID(b.ManagerID, "manager_") || !enrollmentcrypto.ValidID(b.DeviceID, "agent_") || !ValidDigest(b.IncarnationDigest) || !enrollmentcrypto.ValidID(b.ExecutorID, "executor_") || !ValidDigest(b.ExecutorKeyID) || !ValidDigest(b.KeyID) || b.KeyID == b.ExecutorKeyID || !enrollmentcrypto.ValidID(b.DeliveryGrantID, "grant_") || !enrollmentcrypto.ValidID(b.InstallGrantID, "grant_") || b.DeliveryGrantID == b.InstallGrantID {
		return ErrInvalid
	}
	return nil
}
func ValidBinding(b Binding) bool { return b.Validate() == nil }

type Grant struct {
	MutationPlanDigest      string  `json:"mutationPlanDigest,omitempty"`
	PeerBindingDigest       string  `json:"peerBindingDigest,omitempty"`
	Version                 string  `json:"version"`
	Binding                 Binding `json:"binding"`
	DeliveryEnabled         bool    `json:"deliveryEnabled"`
	InstallEnabled          bool    `json:"installEnabled"`
	DeliveryAcknowledged    bool    `json:"deliveryAcknowledged"`
	InstallAcknowledged     bool    `json:"installAcknowledged"`
	ServiceRiskAcknowledged bool    `json:"serviceRiskAcknowledged"`
	ExpiresAt               int64   `json:"expiresAt"`
}

func (g Grant) Validate() error {
	if !(g.Version == GrantVersion && g.MutationPlanDigest == "" && g.PeerBindingDigest == "" || g.Version == CoordinatedGrantVersion && ValidDigest(g.MutationPlanDigest) && ValidDigest(g.PeerBindingDigest)) || g.Binding.Validate() != nil || !ValidTime(g.ExpiresAt) || g.DeliveryEnabled && (!g.DeliveryAcknowledged || !g.ServiceRiskAcknowledged) || g.InstallEnabled && (!g.InstallAcknowledged || !g.ServiceRiskAcknowledged) {
		return ErrInvalid
	}
	return nil
}

// Permit is immutable and bound to the leaf authenticated when signed. Renewal
// can transport only a still-valid same-identity permit; it never extends expiry.
// The endpoint requires the current signed leaf attestation on each relay call.
type Permit struct {
	SynchronousReviewDigest string    `json:"synchronousReviewDigest,omitempty"`
	Version                 string    `json:"version"`
	Kind                    string    `json:"kind"`
	TransferID              string    `json:"transferId"`
	Binding                 Binding   `json:"binding"`
	LeafDigest              string    `json:"leafDigest"`
	Package                 Selection `json:"package"`
	NativeAcceptanceDigest  string    `json:"nativeAcceptanceDigest"`
	ActorID                 string    `json:"actorId"`
	IssuedAt                int64     `json:"issuedAt"`
	ExpiresAt               int64     `json:"expiresAt"`
	Sequence                uint64    `json:"sequence,string"`
	MaintenanceUntil        int64     `json:"maintenanceUntil"`
	ReadinessDigest         string    `json:"readinessDigest"`
	PackageReviewAccepted   bool      `json:"packageReviewAccepted"`
	TermsAccepted           bool      `json:"termsAccepted"`
}

func (p Permit) Validate() error {
	if p.Version != Version || !ValidTransferID(p.TransferID) || p.Binding.Validate() != nil || !ValidDigest(p.LeafDigest) || !ValidSelection(p.Package) || !ValidDigest(p.NativeAcceptanceDigest) || !enrollmentcrypto.ValidID(p.ActorID, "operator_") || !ValidTime(p.IssuedAt) || !ValidTime(p.ExpiresAt) || p.ExpiresAt <= p.IssuedAt {
		return ErrInvalid
	}
	if p.SynchronousReviewDigest != "" && p.SynchronousReviewDigest != SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest) {
		return ErrInvalid
	}
	switch p.Kind {
	case "deliver":
		if p.SynchronousReviewDigest != "" || p.ExpiresAt-p.IssuedAt > int64(DeliveryLifetime/time.Second) || p.Sequence != 0 || p.MaintenanceUntil != 0 || p.ReadinessDigest != "" || p.PackageReviewAccepted || p.TermsAccepted {
			return ErrInvalid
		}
	case "readiness":
		if p.Sequence == 0 || p.ExpiresAt-p.IssuedAt > 60 || !ValidTime(p.MaintenanceUntil) || p.MaintenanceUntil <= p.IssuedAt || p.MaintenanceUntil-p.IssuedAt > 600 || p.ExpiresAt > p.MaintenanceUntil || p.ReadinessDigest != "" || !p.PackageReviewAccepted || !p.TermsAccepted {
			return ErrInvalid
		}
	case "install":
		if p.Sequence == 0 || p.ExpiresAt-p.IssuedAt > 60 || !ValidTime(p.MaintenanceUntil) || p.MaintenanceUntil <= p.IssuedAt || p.MaintenanceUntil-p.IssuedAt > 600 || p.ExpiresAt > p.MaintenanceUntil || !ValidDigest(p.ReadinessDigest) || !p.PackageReviewAccepted || !p.TermsAccepted {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Report struct {
	Mutation               *fence.Status `json:"mutation,omitempty"`
	Version                string        `json:"version"`
	Kind                   string        `json:"kind"`
	Binding                Binding       `json:"binding"`
	TransferID             string        `json:"transferId"`
	PermitDigest           string        `json:"permitDigest"`
	Package                Selection     `json:"package"`
	NativeAcceptanceDigest string        `json:"nativeAcceptanceDigest"`
	CapturedAt             int64         `json:"capturedAt"`
	Offset                 int64         `json:"offset"`
	State                  string        `json:"state"`
	Readiness              *Readiness    `json:"readiness,omitempty"`
	Result                 *Result       `json:"result,omitempty"`
}

func (r Report) Validate() error {
	if r.Version != Version || r.Binding.Validate() != nil || !ValidTransferID(r.TransferID) || !ValidDigest(r.PermitDigest) || !ValidSelection(r.Package) || !ValidDigest(r.NativeAcceptanceDigest) || !ValidTime(r.CapturedAt) || r.Offset < 0 || r.Offset > r.Package.Size {
		return ErrInvalid
	}
	if r.Kind != "mutation" && r.Mutation != nil {
		return ErrInvalid
	}
	switch r.Kind {
	case "mutation":
		if r.Mutation == nil || r.Mutation.Validate() != nil || r.State != r.Mutation.Phase || r.Readiness != nil || r.Result != nil {
			return ErrInvalid
		}
	case "delivery":
		if r.Readiness != nil || r.Result != nil || (r.State != "imported" && r.State != "intervention_required") || r.State == "imported" && r.Offset != r.Package.Size {
			return ErrInvalid
		}
	case "readiness":
		if r.Readiness == nil || r.Result != nil || r.State != r.Readiness.Reason() || r.Readiness.Validate() != nil || r.Readiness.Selection != r.Package || r.Readiness.CapturedAt != r.CapturedAt || r.Offset != r.Package.Size {
			return ErrInvalid
		}
	case "result":
		if r.Readiness != nil || r.Result == nil || r.Result.Validate() != nil || r.Result.CompletedAt != r.CapturedAt || r.State != r.Result.Outcome || r.Offset != r.Package.Size {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type signedPermit struct {
	Permit    Permit `json:"permit"`
	Signature []byte `json:"signature"`
}
type signedReport struct {
	Report    Report `json:"report"`
	Signature []byte `json:"signature"`
}

func message(domain string, v any) []byte {
	b, _ := json.Marshal(v)
	return append([]byte("Tracebolt managed MSI "+domain+" v1\x00"), b...)
}
func validPrivate(k ed25519.PrivateKey) bool {
	return len(k) == ed25519.PrivateKeySize && bytes.Equal(k, ed25519.NewKeyFromSeed(k[:ed25519.SeedSize]))
}
func SignPermit(p Permit, k ed25519.PrivateKey) ([]byte, error) {
	if p.Validate() != nil || !validPrivate(k) || p.Binding.KeyID != Digest(k.Public().(ed25519.PublicKey)) {
		return nil, ErrAuthority
	}
	return json.Marshal(signedPermit{p, ed25519.Sign(k, message("permit", p))})
}
func VerifyPermit(raw []byte, k ed25519.PublicKey) (Permit, error) {
	var s signedPermit
	if !keyvalidation.Ed25519(k) || Canonical(raw, &s, MaxFrameBytes) != nil || s.Permit.Validate() != nil || s.Permit.Binding.KeyID != Digest(k) || !ed25519.Verify(k, message("permit", s.Permit), s.Signature) {
		return Permit{}, ErrAuthority
	}
	return s.Permit, nil
}
func SignReport(r Report, k ed25519.PrivateKey) ([]byte, error) {
	if r.Validate() != nil || !validPrivate(k) || r.Binding.ExecutorKeyID != Digest(k.Public().(ed25519.PublicKey)) {
		return nil, ErrAuthority
	}
	return json.Marshal(signedReport{r, ed25519.Sign(k, message("report", r))})
}
func VerifyReport(raw []byte, k ed25519.PublicKey) (Report, error) {
	var s signedReport
	if !keyvalidation.Ed25519(k) || Canonical(raw, &s, MaxFrameBytes) != nil || s.Report.Validate() != nil || s.Report.Binding.ExecutorKeyID != Digest(k) || !ed25519.Verify(k, message("report", s.Report), s.Signature) {
		return Report{}, ErrAuthority
	}
	return s.Report, nil
}
func Canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}

type PollResponse struct {
	Permit []byte `json:"permit,omitempty"`
}
type ChunkRequest struct {
	TransferID   string `json:"transferId"`
	Index        uint32 `json:"index"`
	PermitDigest string `json:"permitDigest"`
}
type Chunk struct {
	TransferID   string `json:"transferId"`
	Index        uint32 `json:"index"`
	PermitDigest string `json:"permitDigest"`
	Digest       string `json:"digest"`
	Data         []byte `json:"data"`
}

func (c Chunk) Validate(p Permit) error {
	at := int64(c.Index) * MaxChunkBytes
	if p.Validate() != nil || p.Kind != "deliver" || c.TransferID != p.TransferID || c.Index >= MaxChunks || !ValidDigest(c.PermitDigest) || at >= p.Package.Size || len(c.Data) != int(min(int64(MaxChunkBytes), p.Package.Size-at)) || Digest(c.Data) != c.Digest {
		return ErrInvalid
	}
	return nil
}

type ReportRequest struct {
	Report []byte `json:"report"`
}
type Status struct {
	MutationReport []byte `json:"mutationReport,omitempty"`
	Version        string `json:"version"`
	TransferID     string `json:"transferId"`
	PermitDigest   string `json:"permitDigest"`
	NextChunk      uint32 `json:"nextChunk"`
	State          string `json:"state"`
	Attempted      bool   `json:"attempted"`
	Report         []byte `json:"report,omitempty"`
}

type PreparedPackage interface {
	Inspect(context.Context) (Readiness, error)
	InstallOnce(context.Context) (NativeResult, error)
	Close() error
}
type ExecutorAdapter interface {
	PrepareExact(context.Context, Selection) (PreparedPackage, error)
}

// SynchronousReviewDigest binds explicit package/native review of synchronous,
// no-detached deployment and rollback work. It proves review identity, not safety.
func SynchronousReviewDigest(s Selection, native string) string {
	if !ValidSelection(s) || !ValidDigest(native) {
		return ""
	}
	b, _ := json.Marshal(struct {
		Package     Selection `json:"package"`
		Native      string    `json:"nativeAcceptanceDigest"`
		Attestation string    `json:"attestation"`
	}{s, native, "reviewed synchronous custom actions; no detached deployment or rollback work after native return"})
	return Digest(append([]byte("Tracebolt coordinated MSI review v1\x00"), b...))
}
