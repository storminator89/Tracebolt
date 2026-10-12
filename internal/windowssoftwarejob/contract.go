// Package windowssoftwarejob is the separately granted, exact prepared-MSI job
// domain. Observer and WUA/service-control authority never grant software installs.
package windowssoftwarejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const (
	Version         = "tracebolt.windows-prepared-msi-job.v1"
	Scope           = "windows-prepared-msi-install-v1"
	ConsentVersion  = "tracebolt.windows-prepared-msi-consent.v1"
	MaxJobs         = 1
	MaxBytes        = 128 << 10
	PreviewLifetime = 60 * time.Second
	// Disclosure is a fresh local approval, never an observation receipt upgrade.
	Disclosure = "Allow one separately approved install of this exact locally prepared x64 machine MSI by a dedicated elevated executor. MSI custom actions can execute arbitrary code, access the network, change services and disrupt applications. A hash verifies bytes, not safety or offline behavior. Review this package and its terms and complete package-specific native acceptance first. No download, EXE, transform, patch, upgrade, repair, uninstall, arbitrary property, shell or automatic reboot is provided."
)

var (
	ErrInvalid     = errors.New("windows_software_job_invalid")
	ErrUnavailable = errors.New("windows_software_job_unavailable")
	ErrConflict    = errors.New("windows_software_job_conflict")
	ErrExpired     = errors.New("windows_software_job_expired")
	ErrAuthority   = errors.New("windows_software_job_authority")
	ErrUncertain   = errors.New("windows_software_job_persistence_uncertain")
	ErrIntegrity   = errors.New("windows_software_job_integrity")
	ErrConsumed    = errors.New("windows_software_job_consumed")
)
var guid = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)

// Selection is public package-review metadata, never a path, command, URL or
// installer property bag. Every byte of it is pinned by fresh local consent.
type Selection struct {
	SHA256            string `json:"sha256"`
	Size              int64  `json:"size"`
	ProductCode       string `json:"productCode"`
	PackageCode       string `json:"packageCode"`
	Version           string `json:"version"`
	Architecture      string `json:"architecture"`
	Name              string `json:"name"`
	TermsReviewDigest string `json:"termsReviewDigest"`
	ReviewReference   string `json:"reviewReference"`
}

func boundedText(s string, limit int) bool {
	if len(s) == 0 || len(s) > limit || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func ValidGUID(s string) bool {
	return guid.MatchString(s) && s != "{00000000-0000-0000-0000-000000000000}"
}
func ValidProductVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for i, p := range parts {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || strconv.FormatUint(n, 10) != p || i < 2 && n > 255 {
			return false
		}
	}
	return true
}
func ValidSelection(s Selection) bool {
	return actionpermit.ValidDigest(s.SHA256) && s.Size >= 512 && s.Size <= 128<<20 && ValidGUID(s.ProductCode) && ValidGUID(s.PackageCode) && ValidProductVersion(s.Version) && s.Architecture == "amd64" && boundedText(s.Name, 120) && actionpermit.ValidDigest(s.TermsReviewDigest) && boundedText(s.ReviewReference, 160)
}

type Binding struct {
	ManagerID string `json:"managerId"`
	DeviceID  string `json:"deviceId"`
	// Original immutable identity anchor, not the currently renewed leaf.
	IncarnationDigest string `json:"incarnationDigest"`
	ExecutorID        string `json:"executorId"`
	ExecutorKeyID     string `json:"executorKeyId"`
	GrantID           string `json:"grantId"`
	KeyID             string `json:"keyId"`
}

func ValidBinding(b Binding) bool {
	return enrollmentcrypto.ValidID(b.ManagerID, "manager_") && enrollmentcrypto.ValidID(b.DeviceID, "agent_") && actionpermit.ValidDigest(b.IncarnationDigest) && enrollmentcrypto.ValidID(b.ExecutorID, "executor_") && actionpermit.ValidDigest(b.ExecutorKeyID) && b.ExecutorKeyID != b.KeyID && enrollmentcrypto.ValidID(b.GrantID, "grant_") && actionpermit.ValidDigest(b.KeyID)
}

type Consent struct {
	Package                Selection `json:"package"`
	NativeAcceptanceDigest string    `json:"nativeAcceptanceDigest"`
	PackageReviewAccepted  bool      `json:"packageReviewAccepted"`
	Version                string    `json:"version"`
	Scope                  string    `json:"scope"`
	Binding                Binding   `json:"binding"`
	Enabled                bool      `json:"enabled"`
	Acknowledged           bool      `json:"acknowledged"`
	ExpiresAt              int64     `json:"expiresAt"`
}

func (c Consent) Validate() error {
	if c.Version != ConsentVersion || c.Scope != Scope || !ValidBinding(c.Binding) || !ValidSelection(c.Package) || !actionpermit.ValidDigest(c.NativeAcceptanceDigest) || !validTime(c.ExpiresAt) || c.Enabled && (!c.Acknowledged || !c.PackageReviewAccepted) {
		return ErrInvalid
	}
	return nil
}

// Fact is deliberately tri-state: missing and unknown do not become false.
type Fact string

const (
	Yes     Fact = "yes"
	No      Fact = "no"
	Unknown Fact = "unknown"
)

func fact(f Fact) bool { return f == Yes || f == No || f == Unknown }

type Readiness struct {
	Selection             Selection `json:"selection"`
	CapturedAt            int64     `json:"capturedAt"`
	PackageVerified       Fact      `json:"packageVerified"`
	MachineAbsent         Fact      `json:"machineAbsent"`
	InstallerBusy         Fact      `json:"installerBusy"`
	NativeAcceptance      Fact      `json:"nativeAcceptance"`
	PackageReviewAccepted Fact      `json:"packageReviewAccepted"`
	MaintenanceWindowEnd  int64     `json:"maintenanceWindowEnd"`
}

func (r Readiness) Validate() error {
	if !ValidSelection(r.Selection) || !validTime(r.CapturedAt) || !validTime(r.MaintenanceWindowEnd) {
		return ErrInvalid
	}
	for _, f := range []Fact{r.PackageVerified, r.MachineAbsent, r.InstallerBusy, r.NativeAcceptance, r.PackageReviewAccepted} {
		if !fact(f) {
			return ErrInvalid
		}
	}
	return nil
}
func (r Readiness) Reason() string {
	if r.Validate() != nil {
		return "readiness_unknown"
	}
	for _, f := range []Fact{r.PackageVerified, r.MachineAbsent, r.InstallerBusy, r.NativeAcceptance, r.PackageReviewAccepted} {
		if f == Unknown {
			return "readiness_unknown"
		}
	}
	if r.PackageVerified != Yes {
		return "package_changed"
	}
	if r.MachineAbsent != Yes {
		return "already_registered"
	}
	if r.NativeAcceptance != Yes || r.PackageReviewAccepted != Yes {
		return "package_review_required"
	}
	if r.InstallerBusy != No {
		return "installer_busy"
	}
	if r.CapturedAt >= r.MaintenanceWindowEnd {
		return "maintenance_window_expired"
	}
	return "ready"
}

// SameFacts ignores only the new read's capture time; changed facts need review.
func SameFacts(a, b Readiness) bool { a.CapturedAt = 0; b.CapturedAt = 0; return a == b }

type Preview struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actorId"`
	Binding   Binding   `json:"binding"`
	Readiness Readiness `json:"readiness"`
	CreatedAt int64     `json:"createdAt"`
	ExpiresAt int64     `json:"expiresAt"`
	Digest    string    `json:"digest"`
}

func digest(v any) string { raw, _ := json.Marshal(v); return actionpermit.Digest(raw) }
func previewDigest(p Preview) string {
	p.Digest = ""
	raw, _ := json.Marshal(p)
	return actionpermit.Digest(append([]byte("Tracebolt selected MSI preview v1\x00"), raw...))
}
func validTime(n int64) bool { return n > 0 && n <= 253402300799 }
func (p Preview) Validate() error {
	if !enrollmentcrypto.ValidID(p.ID, "software_") || !enrollmentcrypto.ValidID(p.ActorID, "operator_") || !ValidBinding(p.Binding) || p.Readiness.Validate() != nil || !validTime(p.CreatedAt) || !validTime(p.ExpiresAt) || p.Readiness.CapturedAt > p.CreatedAt || p.CreatedAt-p.Readiness.CapturedAt > 60 || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt-p.CreatedAt > 60 || p.ExpiresAt > p.Readiness.MaintenanceWindowEnd || p.Digest != previewDigest(p) {
		return ErrInvalid
	}
	return nil
}

type Permit struct {
	Version    string  `json:"version"`
	Preview    Preview `json:"preview"`
	Sequence   uint64  `json:"sequence,string"`
	ApprovedAt int64   `json:"approvedAt"`
}

func (p Permit) Validate() error {
	if p.Version != Version || p.Preview.Validate() != nil || p.Preview.Readiness.Reason() != "ready" || p.Sequence != 1 || p.ApprovedAt < p.Preview.CreatedAt || p.ApprovedAt >= p.Preview.ExpiresAt {
		return ErrInvalid
	}
	return nil
}
func (p Permit) IssuedAt() int64 { return p.ApprovedAt }

type envelope struct {
	Permit    Permit `json:"permit"`
	Signature string `json:"signature"`
}

func signingMessage(p Permit) []byte {
	raw, _ := json.Marshal(p)
	return append([]byte("Tracebolt selected prepared MSI install v1\x00"), raw...)
}
func Sign(p Permit, k ed25519.PrivateKey) ([]byte, error) {
	if p.Validate() != nil || len(k) != ed25519.PrivateKeySize || !bytes.Equal(k, ed25519.NewKeyFromSeed(k[:ed25519.SeedSize])) || p.Preview.Binding.KeyID != actionpermit.Digest(k.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	return json.Marshal(envelope{p, base64.RawStdEncoding.EncodeToString(ed25519.Sign(k, signingMessage(p)))})
}
func Verify(raw []byte, k ed25519.PublicKey) (Permit, error) {
	var e envelope
	if !keyvalidation.Ed25519(k) || canonical(raw, &e, 8192) != nil || e.Permit.Validate() != nil || e.Permit.Preview.Binding.KeyID != actionpermit.Digest(k) {
		return Permit{}, ErrInvalid
	}
	sig, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(sig) != e.Signature || !ed25519.Verify(k, signingMessage(e.Permit), sig) {
		return Permit{}, ErrAuthority
	}
	return e.Permit, nil
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrInvalid
	}
	return nil
}
