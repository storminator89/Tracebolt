// Package actionpermit defines an inert, strictly versioned command-permit
// contract. It neither authenticates operators nor loads host authority, signs
// permits, opens sockets, or executes actions. See docs/controlled-action-core.md.
package actionpermit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const (
	Version               = "tracebolt.execution-permit.v1"
	VersionV2             = "tracebolt.execution-permit.v2"
	PlanVersionV2         = "tracebolt.action-plan.v2"
	FullAdminServiceScope = "control-existing-root-trusted-system-services"
	PlanVersion           = "tracebolt.action-plan.v1"
	TryRestartService     = "service.try-restart"
	MaxPermitBytes        = 4096
	MaxAffectedServices   = 64
	MaxLifetimeSeconds    = 120
	MaxFutureSkewSeconds  = 5
	signingDomain         = "Tracebolt controlled action execution permit v1\x00"
	maxUnix               = 253402300799
)

var (
	ErrInvalid   = errors.New("action_permit_invalid")
	ErrSignature = errors.New("action_permit_signature_invalid")
	ErrBinding   = errors.New("action_permit_local_binding_mismatch")
	ErrDisabled  = errors.New("action_permit_disabled")
	ErrExpired   = errors.New("action_permit_expired")
	ErrNotReady  = errors.New("action_permit_not_ready")
	ErrClock     = errors.New("action_permit_clock_invalid")
)

// Plan is deliberately a single typed action. UnitPolicyDigest commits to the
// locally reviewed effective unit, dependencies and execution inputs. A digest
// does not itself validate those inputs; the helper separately checks reviewed
// pins and current unit state. It does not prove local review completeness.
// There are no arbitrary commands, paths, options, environment or extension maps.
type Plan struct {
	Version                string `json:"version"`
	Action                 string `json:"action"`
	Unit                   string `json:"unit"`
	UnitPolicyDigest       string `json:"unitPolicyDigest"`
	AffectedServicesDigest string `json:"affectedServicesDigest,omitempty"`
}

// Permit is an immutable description, never proof of authorization on its own.
// The manager must derive OperatorID and ApprovalDigest from authenticated
// server state. IncarnationDigest must identify the locally pinned enrollment
// incarnation, not a reusable hostname or manager-controlled display label.
type Permit struct {
	Version           string `json:"version"`
	ManagerID         string `json:"managerId"`
	KeyID             string `json:"keyId"`
	EndpointID        string `json:"endpointId"`
	IncarnationDigest string `json:"incarnationDigest"`
	JobID             string `json:"jobId"`
	Sequence          uint64 `json:"sequence,string"`
	Plan              Plan   `json:"plan"`
	PlanDigest        string `json:"planDigest"`
	OperatorID        string `json:"operatorId"`
	ApprovalDigest    string `json:"approvalDigest"`
	RootPolicyDigest  string `json:"rootPolicyDigest"`
	IssuedAt          int64  `json:"issuedAt"`
	NotBefore         int64  `json:"notBefore"`
	StartDeadline     int64  `json:"startDeadline"`
}

type envelope struct {
	Permit    Permit `json:"permit"`
	Signature string `json:"signature"`
}

// LocalPins is trusted local-adapter input, NEVER a request body. Constructing
// it is not evidence of root protection, consent, peer identity or TLS. The
// helper must independently load/revalidate those facts before any start.
// The actionhelper runtime supplies that adapter; these Go inputs alone remain
// no proof of root authority or transport security. Enabled defaults to false.
type LocalPins struct {
	Enabled              bool
	ManagerID            string
	PublicKey            ed25519.PublicKey
	EndpointID           string
	IncarnationDigest    string
	RootPolicyDigest     string
	MaxLifetimeSeconds   int64
	MaxFutureSkewSeconds int64
	Services             []ServiceRule
	// Scope is a separately loaded v2 root grant, never a permit field.
	Scope string
}

type ServiceRule struct {
	Unit             string
	UnitPolicyDigest string
}

// Verifier holds a defensive snapshot of explicitly supplied local pins. It
// cannot discover or establish authority, and never obtains a key from a permit.
type Verifier struct{ pins *LocalPins }

func ValidDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && enrollmentcrypto.ValidHash(strings.TrimPrefix(s, "sha256:"))
}

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validUnit(unit string) bool {
	if len(unit) < len("a.service") || len(unit) > 128 || !strings.HasSuffix(unit, ".service") {
		return false
	}
	for i, c := range []byte(strings.TrimSuffix(unit, ".service")) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if i > 0 && (c == '_' || c == '-' || c == '.') {
			continue
		}
		return false
	}
	return true
}

// AffectedServicesDigest binds the exact canonical impact projection independently
// of the opaque root configuration digest. V2 helpers recompute this from their
// trusted graph; a reporter cannot shorten the visible list while retaining an
// otherwise genuine configuration digest. No sorting/deduplication hides input.
func AffectedServicesDigest(units []string) (string, error) {
	if len(units) < 1 || len(units) > MaxAffectedServices {
		return "", ErrInvalid
	}
	last := ""
	for _, unit := range units {
		if !validUnit(unit) || unit <= last {
			return "", ErrInvalid
		}
		last = unit
	}
	raw, err := json.Marshal(struct {
		Version  string   `json:"version"`
		Services []string `json:"services"`
	}{"tracebolt.service-action-affected-services.v2", units})
	if err != nil {
		return "", ErrInvalid
	}
	return Digest(raw), nil
}

func PlanDigest(p Plan) (string, error) {
	if (p.Version != PlanVersion && p.Version != PlanVersionV2) || p.Action != TryRestartService || !validUnit(p.Unit) || !ValidDigest(p.UnitPolicyDigest) || (p.Version == PlanVersion && p.AffectedServicesDigest != "") || (p.Version == PlanVersionV2 && !ValidDigest(p.AffectedServicesDigest)) {
		return "", ErrInvalid
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalid
	}
	return Digest(b), nil
}

func valid(p Permit) bool {
	d, err := PlanDigest(p.Plan)
	return err == nil && ((p.Version == Version && p.Plan.Version == PlanVersion) || (p.Version == VersionV2 && p.Plan.Version == PlanVersionV2)) && enrollmentcrypto.ValidID(p.ManagerID, "manager_") &&
		ValidDigest(p.KeyID) && enrollmentcrypto.ValidID(p.EndpointID, "agent_") && ValidDigest(p.IncarnationDigest) &&
		enrollmentcrypto.ValidID(p.JobID, "action_") && p.Sequence != 0 && d == p.PlanDigest &&
		enrollmentcrypto.ValidID(p.OperatorID, "operator_") && ValidDigest(p.ApprovalDigest) && ValidDigest(p.RootPolicyDigest) &&
		p.IssuedAt > 0 && p.IssuedAt <= p.NotBefore && p.NotBefore < p.StartDeadline && p.StartDeadline <= maxUnix &&
		p.StartDeadline-p.IssuedAt <= MaxLifetimeSeconds
}

// SigningMessage provides the exact domain-separated bytes to an independently
// authorized signer. It does not sign, create keys, or establish approval.
func SigningMessage(p Permit) ([]byte, error) {
	if !valid(p) {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, ErrInvalid
	}
	domain := signingDomain
	if p.Version == VersionV2 {
		domain = "Tracebolt controlled action execution permit v2\x00"
	}
	return append([]byte(domain), b...), nil
}

// Encode accepts an already-created signature; Decode enforces this one native
// canonical encoding, including field order, integer spelling and base64 form.
func Encode(p Permit, signature []byte) ([]byte, error) {
	if !valid(p) || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(envelope{p, base64.RawStdEncoding.EncodeToString(signature)})
	if err != nil || len(b) > MaxPermitBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

// Decode is shape validation, NOT signature verification or execution authority.
func Decode(raw []byte) (Permit, error) {
	p, _, err := decode(raw)
	return p, err
}

func decode(raw []byte) (Permit, []byte, error) {
	var e envelope
	if len(raw) == 0 || len(raw) > MaxPermitBytes || json.Unmarshal(raw, &e) != nil {
		return Permit{}, nil, ErrInvalid
	}
	sig, err := base64.RawStdEncoding.DecodeString(e.Signature)
	canonical, encErr := Encode(e.Permit, sig)
	// Byte equality rejects unknown/missing/duplicate/case-folded keys, null,
	// trailing bytes, whitespace, invalid UTF-8, and alternate escape encodings.
	if err != nil || encErr != nil || !bytes.Equal(raw, canonical) {
		return Permit{}, nil, ErrInvalid
	}
	return e.Permit, sig, nil
}

func NewVerifier(p LocalPins) (Verifier, error) {
	if !enrollmentcrypto.ValidID(p.ManagerID, "manager_") || !keyvalidation.Ed25519(p.PublicKey) ||
		!enrollmentcrypto.ValidID(p.EndpointID, "agent_") || !ValidDigest(p.IncarnationDigest) || !ValidDigest(p.RootPolicyDigest) ||
		p.MaxLifetimeSeconds < 1 || p.MaxLifetimeSeconds > MaxLifetimeSeconds || p.MaxFutureSkewSeconds < 0 ||
		p.MaxFutureSkewSeconds > MaxFutureSkewSeconds || (p.Scope != "" && p.Scope != FullAdminServiceScope) || (p.Scope == "" && (len(p.Services) == 0 || len(p.Services) > 16)) || (p.Scope == FullAdminServiceScope && len(p.Services) != 0) {
		return Verifier{}, ErrInvalid
	}
	last := ""
	for _, rule := range p.Services {
		if !validUnit(rule.Unit) || rule.Unit <= last || !ValidDigest(rule.UnitPolicyDigest) {
			return Verifier{}, ErrInvalid
		}
		last = rule.Unit
	}
	p.PublicKey = bytes.Clone(p.PublicKey)
	p.Services = append([]ServiceRule(nil), p.Services...)
	return Verifier{&p}, nil
}

// BindingDigest binds an action ledger to its manager, key and endpoint
// incarnation. Policy/allowlist changes must not reset the consumption floor.
func (v Verifier) BindingDigest() (string, error) {
	if v.pins == nil {
		return "", ErrInvalid
	}
	p := v.pins
	b, err := json.Marshal(struct {
		Domain            string
		ManagerID         string
		KeyID             string
		EndpointID        string
		IncarnationDigest string
	}{"tracebolt.action-ledger-binding.v1", p.ManagerID, Digest(p.PublicKey), p.EndpointID, p.IncarnationDigest})
	if err != nil {
		return "", ErrInvalid
	}
	return Digest(b), nil
}

// Verify checks signature and current local policy, but not wall time or durable
// replay state. Its result must never be used directly to launch a host action.
func (v Verifier) Verify(raw []byte) (Permit, error) {
	if v.pins == nil {
		return Permit{}, ErrInvalid
	}
	if !v.pins.Enabled {
		return Permit{}, ErrDisabled
	}
	p, err := v.CheckSignature(raw)
	if err != nil {
		return Permit{}, err
	}
	c := v.pins
	if p.RootPolicyDigest != c.RootPolicyDigest ||
		p.StartDeadline-p.IssuedAt > c.MaxLifetimeSeconds {
		return Permit{}, ErrBinding
	}
	allowed := c.Scope == FullAdminServiceScope && p.Version == VersionV2
	if c.Scope == "" && p.Version != Version {
		return Permit{}, ErrBinding
	}
	for _, rule := range c.Services {
		if rule.Unit == p.Plan.Unit && rule.UnitPolicyDigest == p.Plan.UnitPolicyDigest {
			allowed = true
		}
	}
	if !allowed {
		return Permit{}, ErrBinding
	}
	return p, nil
}

// CheckSignature authenticates historical metadata only: it intentionally does
// NOT check enabled state, current policy, time or replay state. It supports
// reading old status after policy revocation, not admitting or starting work.
func (v Verifier) CheckSignature(raw []byte) (Permit, error) {
	if v.pins == nil {
		return Permit{}, ErrInvalid
	}
	p, signature, err := decode(raw)
	if err != nil {
		return Permit{}, err
	}
	c := v.pins
	if p.ManagerID != c.ManagerID || p.KeyID != Digest(c.PublicKey) || p.EndpointID != c.EndpointID ||
		p.IncarnationDigest != c.IncarnationDigest {
		return Permit{}, ErrBinding
	}
	message, err := SigningMessage(p)
	if err != nil || !ed25519.Verify(c.PublicKey, message, signature) {
		return Permit{}, ErrSignature
	}
	return p, nil
}

// CheckTime checks an already verified permit against the caller's current
// local clock. Durable actionstate additionally rejects clock reversal. Deadline
// is exclusive and bounds a future start, never the lifetime of a running job.
func (v Verifier) CheckTime(p Permit, now time.Time) error {
	if v.pins == nil || !valid(p) {
		return ErrInvalid
	}
	if now.Unix() <= 0 || now.Unix() > maxUnix || now.Location() != time.UTC {
		return ErrClock
	}
	if p.IssuedAt > now.Unix()+v.pins.MaxFutureSkewSeconds {
		return ErrClock
	}
	if now.Unix() < p.NotBefore {
		return ErrNotReady
	}
	if now.Unix() >= p.StartDeadline {
		return ErrExpired
	}
	return nil
}

// RootPolicyDigest returns immutable verifier-snapshot metadata, never authority
// to start an action. Runtimes use it to avoid advertising a newer live policy
// while their durable state's verifier still holds an older grant snapshot.
func (v Verifier) RootPolicyDigest() (string, error) {
	if v.pins == nil {
		return "", ErrInvalid
	}
	return v.pins.RootPolicyDigest, nil
}
