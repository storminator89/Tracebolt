// Package windowsupdatejob is the source-only selected cached-WUA update job
// domain. Enrollment-owned manager persistence and TLS relay are separate
// integrations; no native elevated installer/provisioner is supplied.
// Observation and service-control grants never apply.
package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const (
	Version                 = "tracebolt.windows-selected-update-job.v1"
	Scope                   = "windows-selected-cached-update-install-v1"
	ConsentVersion          = "tracebolt.windows-selected-update-consent.v1"
	ScheduledConsentVersion = "tracebolt.windows-selected-update-consent.v2"
	ScheduledPermitVersion  = "tracebolt.windows-selected-update-job.v2"
	ScheduleScope           = "windows-selected-cached-update-schedule-v1"
	MaxJobs                 = 32
	MaxBytes                = 512 << 10
	PreviewLifetime         = 60 * time.Second
	// Disclosure is a fresh local approval, never an observation receipt upgrade.
	Disclosure = "Allow separately approved installation of one exact cached Windows software update through a dedicated elevated executor. Installation may interrupt applications and require a later restart. Only already-downloaded, already-accepted-license, noninteractive, non-bundled updates that require no source media or network are eligible. No downloads, license acceptance, forced application closure, automatic reboot, service-control grant or arbitrary command is authorized."
)

var (
	ErrInvalid     = errors.New("windows_update_job_invalid")
	ErrUnavailable = errors.New("windows_update_job_unavailable")
	ErrConflict    = errors.New("windows_update_job_conflict")
	ErrExpired     = errors.New("windows_update_job_expired")
	ErrAuthority   = errors.New("windows_update_job_authority")
	ErrUncertain   = errors.New("windows_update_job_persistence_uncertain")
	ErrIntegrity   = errors.New("windows_update_job_integrity")
	ErrConsumed    = errors.New("windows_update_job_consumed")
)
var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Selection struct {
	UpdateID string `json:"updateId"`
	Revision uint32 `json:"revision"`
}

func ValidSelection(s Selection) bool {
	return guid.MatchString(s.UpdateID) && s.UpdateID != "00000000-0000-0000-0000-000000000000" && s.Revision <= 2147483647
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

const ScheduledBackgroundConsentVersion = "tracebolt.windows-selected-update-consent.v5"

const BackgroundConsentVersion = "tracebolt.windows-selected-update-consent.v4"

const CoordinatedConsentVersion = "tracebolt.windows-selected-update-consent.v3"

type Consent struct {
	BackgroundAcknowledged bool    `json:"backgroundAcknowledged,omitempty"`
	MutationPlanDigest     string  `json:"mutationPlanDigest,omitempty"`
	PeerBindingDigest      string  `json:"peerBindingDigest,omitempty"`
	Version                string  `json:"version"`
	Scope                  string  `json:"scope"`
	Binding                Binding `json:"binding"`
	Enabled                bool    `json:"enabled"`
	Acknowledged           bool    `json:"acknowledged"`
	ExpiresAt              int64   `json:"expiresAt"`
	ScheduleScope          string  `json:"scheduleScope,omitempty"`
	ScheduleAcknowledged   bool    `json:"scheduleAcknowledged,omitempty"`
}

func (c Consent) Background() bool {
	return c.Version == BackgroundConsentVersion || c.Version == ScheduledBackgroundConsentVersion
}

func (c Consent) Validate() error {
	if c.Background() != c.BackgroundAcknowledged || !(c.Version == ConsentVersion && c.MutationPlanDigest == "" && c.PeerBindingDigest == "" && c.ScheduleScope == "" && !c.ScheduleAcknowledged || c.Version == ScheduledConsentVersion && c.MutationPlanDigest == "" && c.PeerBindingDigest == "" && c.ScheduleScope == ScheduleScope && c.ScheduleAcknowledged || (c.Version == CoordinatedConsentVersion || c.Version == BackgroundConsentVersion) && actionpermit.ValidDigest(c.MutationPlanDigest) && actionpermit.ValidDigest(c.PeerBindingDigest) && c.ScheduleScope == "" && !c.ScheduleAcknowledged || c.Version == ScheduledBackgroundConsentVersion && actionpermit.ValidDigest(c.MutationPlanDigest) && actionpermit.ValidDigest(c.PeerBindingDigest) && c.ScheduleScope == ScheduleScope && c.ScheduleAcknowledged) || c.Scope != Scope || !ValidBinding(c.Binding) || !validTime(c.ExpiresAt) || c.Enabled && !c.Acknowledged {
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
	Selection           Selection `json:"selection"`
	CapturedAt          int64     `json:"capturedAt"`
	Software            Fact      `json:"software"`
	Installed           Fact      `json:"installed"`
	Hidden              Fact      `json:"hidden"`
	Downloaded          Fact      `json:"downloaded"`
	EULAAccepted        Fact      `json:"eulaAccepted"`
	CanRequestUserInput Fact      `json:"canRequestUserInput"`
	CanRequireSource    Fact      `json:"canRequireSource"`
	RequiresNetwork     Fact      `json:"requiresNetwork"`
	// -1 means unreadable. The first increment rejects all bundles.
	BundledCount         int32 `json:"bundledCount"`
	InstallerBusy        Fact  `json:"installerBusy"`
	RebootRequiredBefore Fact  `json:"rebootRequiredBefore"`
	// WUA InstallationRebootBehavior: never, always, can, or unknown.
	RebootBehavior  string `json:"rebootBehavior"`
	OfflineVerified Fact   `json:"offlineVerified"`
}

func (r Readiness) Validate() error {
	if !ValidSelection(r.Selection) || !validTime(r.CapturedAt) || r.BundledCount < -1 {
		return ErrInvalid
	}
	for _, f := range []Fact{r.Software, r.Installed, r.Hidden, r.Downloaded, r.EULAAccepted, r.CanRequestUserInput, r.CanRequireSource, r.RequiresNetwork, r.InstallerBusy, r.RebootRequiredBefore, r.OfflineVerified} {
		if !fact(f) {
			return ErrInvalid
		}
	}
	switch r.RebootBehavior {
	case "never", "always", "can", "unknown":
	default:
		return ErrInvalid
	}
	return nil
}
func (r Readiness) Reason() string {
	if r.Validate() != nil {
		return "readiness_unknown"
	}
	for _, f := range []Fact{r.Software, r.Installed, r.Hidden, r.Downloaded, r.EULAAccepted, r.CanRequestUserInput, r.CanRequireSource, r.RequiresNetwork, r.InstallerBusy, r.RebootRequiredBefore, r.OfflineVerified} {
		if f == Unknown {
			return "readiness_unknown"
		}
	}
	if r.BundledCount < 0 || r.RebootBehavior == "unknown" {
		return "readiness_unknown"
	}
	if r.OfflineVerified != Yes {
		return "offline_unverified"
	}
	if r.Software != Yes || r.Installed != No || r.Hidden != No {
		return "selection_ineligible"
	}
	if r.Downloaded != Yes {
		return "not_downloaded"
	}
	if r.EULAAccepted != Yes {
		return "license_not_accepted"
	}
	if r.BundledCount != 0 {
		return "bundle_unsupported"
	}
	if r.CanRequestUserInput != No || r.CanRequireSource != No || r.RequiresNetwork != No {
		return "interaction_or_source_required"
	}
	if r.InstallerBusy != No {
		return "installer_busy"
	}
	if r.RebootRequiredBefore != No {
		return "restart_required_before"
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
	return actionpermit.Digest(append([]byte("Tracebolt selected WUA preview v1\x00"), raw...))
}
func validTime(n int64) bool { return n > 0 && n <= 253402300799 }
func (p Preview) Validate() error {
	if !enrollmentcrypto.ValidID(p.ID, "update_") || !enrollmentcrypto.ValidID(p.ActorID, "operator_") || !ValidBinding(p.Binding) || p.Readiness.Validate() != nil || !validTime(p.CreatedAt) || !validTime(p.ExpiresAt) || p.Readiness.CapturedAt > p.CreatedAt || p.CreatedAt-p.Readiness.CapturedAt > 60 || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt-p.CreatedAt > 60 || p.Digest != previewDigest(p) {
		return ErrInvalid
	}
	return nil
}

type Permit struct {
	Version        string            `json:"version"`
	Preview        Preview           `json:"preview"`
	Sequence       uint64            `json:"sequence,string"`
	ApprovedAt     int64             `json:"approvedAt"`
	PermitIssuedAt int64             `json:"permitIssuedAt,omitempty"`
	Schedule       *ScheduleApproval `json:"schedule,omitempty"`
}

func (p Permit) Validate() error {
	if p.Schedule != nil {
		return p.validateScheduled()
	}
	if p.Version != Version || p.PermitIssuedAt != 0 || p.Preview.Validate() != nil || p.Preview.Readiness.Reason() != "ready" || p.Sequence == 0 || p.ApprovedAt < p.Preview.CreatedAt || p.ApprovedAt >= p.Preview.ExpiresAt {
		return ErrInvalid
	}
	return nil
}

type envelope struct {
	Permit    Permit `json:"permit"`
	Signature string `json:"signature"`
}

func signingMessage(p Permit) []byte {
	raw, _ := json.Marshal(p)
	if p.Version == ScheduledPermitVersion {
		return append([]byte("Tracebolt scheduled cached WUA install v2\x00"), raw...)
	}
	return append([]byte("Tracebolt selected cached WUA install v1\x00"), raw...)
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
