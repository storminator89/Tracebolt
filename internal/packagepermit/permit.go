// Package packagepermit authenticates package-only preparation and execution
// authority. Its domain and bounds never widen the service-only action permit.
package packagepermit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/packageplan"
)

const (
	Version                      = "tracebolt.native-package-permit.v1"
	Prepare                      = "package.prepare-selected"
	Execute                      = packageplan.Action
	MaxEnvelopeBytes             = 192 << 10
	MaxPreparationLifetime int64 = 120
	domain                       = "Tracebolt native package permit v1\x00"
)

var (
	ErrInvalid      = errors.New("package_permit_invalid")
	ErrUnauthorized = errors.New("package_permit_unauthorized")
	ErrExpired      = errors.New("package_permit_expired")
	namePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)
)

type Selection struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
}
type Permit struct {
	Version           string            `json:"version"`
	Action            string            `json:"action"`
	ManagerID         string            `json:"managerId"`
	KeyID             string            `json:"keyId"`
	EndpointID        string            `json:"endpointId"`
	IncarnationDigest string            `json:"incarnationDigest"`
	RootPolicyDigest  string            `json:"rootPolicyDigest"`
	JobID             string            `json:"jobId"`
	Sequence          uint64            `json:"sequence,string"`
	ActorID           string            `json:"actorId"`
	PreviewDigest     string            `json:"previewDigest"`
	IssuedAt          int64             `json:"issuedAt"`
	NotBefore         int64             `json:"notBefore"`
	StartDeadline     int64             `json:"startDeadline"`
	Selection         []Selection       `json:"selection"`
	Plan              *packageplan.Plan `json:"plan"`
	PlanDigest        string            `json:"planDigest"`
}
type envelope struct {
	Permit    Permit `json:"permit"`
	Signature []byte `json:"signature"`
}
type Pins struct {
	ManagerID, EndpointID, IncarnationDigest, RootPolicyDigest string
	PublicKey                                                  ed25519.PublicKey
	Allowed                                                    []Selection
}

func validTime(t int64) bool { return t > 0 && t <= 253402300799 }
func validSelection(ss []Selection) bool {
	if len(ss) == 0 || len(ss) > packageplan.MaxPackages {
		return false
	}
	lastName, lastArch := "", ""
	for _, s := range ss {
		if !namePattern.MatchString(s.Name) || s.Architecture != "amd64" || s.Name < lastName || s.Name == lastName && s.Architecture <= lastArch {
			return false
		}
		lastName, lastArch = s.Name, s.Architecture
	}
	return true
}
func validate(ctx context.Context, p Permit) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if p.Version != Version || !enrollmentcrypto.ValidID(p.ManagerID, "manager_") || !enrollmentcrypto.ValidID(p.EndpointID, "agent_") || !enrollmentcrypto.ValidID(p.JobID, "update_") || !enrollmentcrypto.ValidID(p.ActorID, "operator_") || p.Sequence == 0 || !validTime(p.IssuedAt) || p.NotBefore != p.IssuedAt || !validTime(p.StartDeadline) || p.StartDeadline <= p.IssuedAt || p.StartDeadline-p.IssuedAt > MaxPreparationLifetime || !validSelection(p.Selection) {
		return ErrInvalid
	}
	for _, d := range []string{p.KeyID, p.IncarnationDigest, p.RootPolicyDigest} {
		if !actionpermit.ValidDigest(d) {
			return ErrInvalid
		}
	}
	switch p.Action {
	case Prepare:
		if p.Plan != nil || p.PlanDigest != "" || p.PreviewDigest != "" {
			return ErrInvalid
		}
	case Execute:
		if p.Plan == nil || !actionpermit.ValidDigest(p.PreviewDigest) {
			return ErrInvalid
		}
		plan := *p.Plan
		d, e := packageplan.Digest(ctx, plan)
		if e != nil || d != p.PlanDigest || plan.EndpointID != p.EndpointID || plan.IncarnationDigest != p.IncarnationDigest || plan.RootPolicyDigest != p.RootPolicyDigest || plan.Release != "debian-13-trixie" || p.IssuedAt < plan.CreatedAt || p.StartDeadline > plan.ExpiresAt || len(plan.Packages) != len(p.Selection) {
			return ErrInvalid
		}
		for i, u := range plan.Packages {
			if u.Name != p.Selection[i].Name || u.Architecture != p.Selection[i].Architecture {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}
func Message(ctx context.Context, p Permit) ([]byte, error) {
	if e := validate(ctx, p); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxEnvelopeBytes-1024 {
		return nil, ErrInvalid
	}
	return append([]byte(domain), raw...), nil
}
func Sign(ctx context.Context, p Permit, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(key, derived) || !keyvalidation.Ed25519(key.Public().(ed25519.PublicKey)) || p.KeyID != actionpermit.Digest(key.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	message, e := Message(ctx, p)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(envelope{p, ed25519.Sign(key, message)})
	if e != nil || len(raw) > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func Decode(ctx context.Context, raw []byte) (Permit, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Permit{}, nil, ErrInvalid
	}
	var v envelope
	if json.Unmarshal(raw, &v) != nil || len(v.Signature) != ed25519.SignatureSize {
		return Permit{}, nil, ErrInvalid
	}
	if _, e := Message(ctx, v.Permit); e != nil {
		return Permit{}, nil, e
	}
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, canonical) {
		return Permit{}, nil, ErrInvalid
	}
	return v.Permit, bytes.Clone(v.Signature), nil
}
func CheckSignature(ctx context.Context, raw []byte, pins Pins) (Permit, error) {
	if !keyvalidation.Ed25519(pins.PublicKey) || !validSelection(pins.Allowed) {
		return Permit{}, ErrInvalid
	}
	p, sig, e := Decode(ctx, raw)
	if e != nil {
		return Permit{}, e
	}
	if p.ManagerID != pins.ManagerID || p.EndpointID != pins.EndpointID || p.IncarnationDigest != pins.IncarnationDigest || p.RootPolicyDigest != pins.RootPolicyDigest || p.KeyID != actionpermit.Digest(pins.PublicKey) {
		return Permit{}, ErrUnauthorized
	}
	allowed := map[Selection]bool{}
	for _, s := range pins.Allowed {
		allowed[s] = true
	}
	for _, s := range p.Selection {
		if !allowed[s] {
			return Permit{}, ErrUnauthorized
		}
	}
	message, _ := Message(ctx, p)
	if !ed25519.Verify(pins.PublicKey, message, sig) {
		return Permit{}, ErrUnauthorized
	}
	return p, nil
}
func Verify(ctx context.Context, raw []byte, pins Pins, now int64) (Permit, error) {
	p, e := CheckSignature(ctx, raw, pins)
	if e != nil {
		return Permit{}, e
	}
	if !validTime(now) || now < p.NotBefore || now >= p.StartDeadline {
		return Permit{}, ErrExpired
	}
	if p.Plan != nil {
		if e = packageplan.CheckFresh(ctx, *p.Plan, now); e != nil {
			return Permit{}, ErrExpired
		}
	}
	return p, nil
}
