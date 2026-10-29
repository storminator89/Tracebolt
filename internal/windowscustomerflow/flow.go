// Package windowscustomerflow defines a source-only transition contract for a
// fresh, customer-bound Windows Read admin installation. It makes no host calls,
// creates no credentials or grants, and does not authorize starting a service.
// Its values are untrusted until a future protected, create-only receipt owner
// atomically records and validates them under the existing local authority rules.
package windowscustomerflow

import (
	"errors"
	"reflect"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsfullsoftware"
)

const Version = "tracebolt.windows-customer-continuation.v1"
const maxTimestamp = int64(253402300499)

var ErrInvalid = errors.New("customer continuation rejected")

type Phase string

const (
	Pending           Phase = "pending"
	ActivationStarted Phase = "activation-started"
	IdentityActive    Phase = "identity-active"
	GrantsStarted     Phase = "grants-started"
	GrantsVerified    Phase = "grants-verified"
	StartupStarted    Phase = "startup-started"
	Completed         Phase = "completed"
	Indeterminate     Phase = "indeterminate"
)

// Binding contains public identifiers and hashes only. The caller must derive
// these from protected local state and the authenticated manager, not from
// device-supplied or unauthenticated network values.
type Binding struct {
	ManagerID, CustomerID, InstallerProfileID, ClaimID string
	ClaimHash, KeyFingerprint, IssuerFingerprint       string
	ProfileDigest, ExecutableDigest, ServiceDigest     string
	DeadlineAt                                         int64
}

// Consent must be assembled only after the user has reviewed and explicitly
// acknowledged both the exact existing v14 scopes and the separate automatic
// finalizer disclosure. This candidate supports TLS only. No default is consent.
type Consent struct {
	Scopes                         lanclient.WindowsCapabilityConsent
	AutomaticFinalizerAcknowledged bool
}

// State is a transition candidate, never proof that a durable receipt exists.
// Started states fence native operations: a lost/unknown result must become
// indeterminate rather than retry, regrant, or start another identity.
type State struct {
	Version                        string
	Binding                        Binding
	Consent                        Consent
	Phase                          Phase
	CreatedAt, UpdatedAt           int64
	ApprovalDigest, IdentityDigest string
	GrantDigests                   []lanclient.WindowsCapabilityGrantDigest
}

// Evidence consists of assertions from the future local coordinator. This
// package cannot independently validate native service ownership, enrollment,
// issuer status or actual grant contents; false or unavailable assertions fail
// closed. The caller must re-read all evidence at the actual operation edge.
type Evidence struct {
	Binding                                                                         Binding
	Consent                                                                         Consent
	ApprovalDigest, IdentityDigest                                                  string
	OriginalReceiptValid, OwnedServiceValid, IssuerCurrent, ApprovalCurrent         bool
	StoppedAndDisabled, ActivatedIdentity, ServiceRunning, StartupAutomaticVerified bool
	GrantDigests                                                                    []lanclient.WindowsCapabilityGrantDigest
}

type Action string

const (
	BeginActivation  Action = "begin-activation"
	FinishActivation Action = "finish-activation"
	BeginGrants      Action = "begin-grants"
	FinishGrants     Action = "finish-grants"
	BeginStartup     Action = "begin-startup"
	FinishStartup    Action = "finish-startup"
	Interrupt        Action = "interrupt"
)

func validBinding(b Binding) bool {
	return enrollmentcrypto.ValidID(b.ManagerID, "manager_") && enrollmentcrypto.ValidID(b.CustomerID, "customer_") && enrollmentcrypto.ValidID(b.InstallerProfileID, "profile_") && enrollmentcrypto.ValidID(b.ClaimID, "claim_") && enrollmentcrypto.ValidHash(b.ClaimHash) && enrollmentcrypto.ValidHash(b.KeyFingerprint) && enrollmentcrypto.ValidHash(b.IssuerFingerprint) && enrollmentcrypto.ValidHash(b.ProfileDigest) && enrollmentcrypto.ValidHash(b.ExecutableDigest) && enrollmentcrypto.ValidHash(b.ServiceDigest) && b.DeadlineAt > 0 && b.DeadlineAt <= maxTimestamp
}

func validConsent(c Consent) bool {
	return c.AutomaticFinalizerAcknowledged && c.Scopes.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV14 && c.Scopes.Validate() == nil && !c.Scopes.InsecureHTTPAcknowledged && reflect.DeepEqual(c.Scopes.Scopes, lanclient.WindowsReadAdminScopesV14())
}

func clone(s State) State {
	s.Consent.Scopes.Scopes = append([]string(nil), s.Consent.Scopes.Scopes...)
	s.GrantDigests = append([]lanclient.WindowsCapabilityGrantDigest(nil), s.GrantDigests...)
	return s
}

func validGrants(c Consent, grants []lanclient.WindowsCapabilityGrantDigest) bool {
	if !validConsent(c) || len(grants) != len(c.Scopes.Scopes)-1 {
		return false
	}
	software, history := "", ""
	for i, g := range grants {
		if g.Scope != c.Scopes.Scopes[i+1] || !enrollmentcrypto.ValidHash(g.SHA256) {
			return false
		}
		if g.Scope == windowsfullsoftware.Scope {
			software = g.SHA256
		}
		if g.Scope == windowsfullsoftware.HistoryScope {
			history = g.SHA256
		}
	}
	return software != "" && software == history
}

// New creates an in-memory pending candidate; it performs no installation.
func New(binding Binding, consent Consent, now time.Time) (State, error) {
	at := now.UTC().Unix()
	if !validBinding(binding) || !validConsent(consent) || at <= 0 || at > maxTimestamp || at >= binding.DeadlineAt {
		return State{}, ErrInvalid
	}
	return clone(State{Version: Version, Binding: binding, Consent: consent, Phase: Pending, CreatedAt: at, UpdatedAt: at}), nil
}

func validState(s State) bool {
	if s.Version != Version || !validBinding(s.Binding) || !validConsent(s.Consent) || s.CreatedAt <= 0 || s.CreatedAt >= s.Binding.DeadlineAt || s.UpdatedAt < s.CreatedAt || s.UpdatedAt > maxTimestamp || (s.Phase != Indeterminate && s.UpdatedAt >= s.Binding.DeadlineAt) {
		return false
	}
	switch s.Phase {
	case Pending:
		return s.ApprovalDigest == "" && s.IdentityDigest == "" && len(s.GrantDigests) == 0
	case ActivationStarted:
		return enrollmentcrypto.ValidHash(s.ApprovalDigest) && s.IdentityDigest == "" && len(s.GrantDigests) == 0
	case IdentityActive, GrantsStarted:
		return enrollmentcrypto.ValidHash(s.ApprovalDigest) && enrollmentcrypto.ValidHash(s.IdentityDigest) && len(s.GrantDigests) == 0
	case GrantsVerified, StartupStarted, Completed:
		return enrollmentcrypto.ValidHash(s.ApprovalDigest) && enrollmentcrypto.ValidHash(s.IdentityDigest) && validGrants(s.Consent, s.GrantDigests)
	case Indeterminate:
		return enrollmentcrypto.ValidHash(s.ApprovalDigest) && ((s.IdentityDigest == "" && len(s.GrantDigests) == 0) || (enrollmentcrypto.ValidHash(s.IdentityDigest) && (len(s.GrantDigests) == 0 || validGrants(s.Consent, s.GrantDigests))))
	default:
		return false
	}
}

// Advance only proposes the next receipt value. The integrating coordinator
// must compare and atomically persist the original bytes before each native
// operation, hold live guards through the operation, and reconcile uncertain
// writes without calling this function as a substitute for OS evidence.
func Advance(current State, action Action, e Evidence, now time.Time) (State, error) {
	at := now.UTC().Unix()
	if !validState(current) || at < current.UpdatedAt || at > maxTimestamp || e.Binding != current.Binding || !reflect.DeepEqual(e.Consent, current.Consent) || !e.OriginalReceiptValid {
		return State{}, ErrInvalid
	}
	next := clone(current)
	// Recording an uncertain outcome is not permission to perform an operation.
	// It remains possible after expiry or authority loss so the failure is visible.
	if action == Interrupt {
		if current.Phase != ActivationStarted && current.Phase != GrantsStarted && current.Phase != StartupStarted {
			return State{}, ErrInvalid
		}
		next.Phase = Indeterminate
		next.UpdatedAt = at
		if !validState(next) {
			return State{}, ErrInvalid
		}
		return next, nil
	}
	if at >= current.Binding.DeadlineAt || !e.OwnedServiceValid || !e.IssuerCurrent || !e.ApprovalCurrent {
		return State{}, ErrInvalid
	}
	switch action {
	case BeginActivation:
		if current.Phase != Pending || !e.StoppedAndDisabled || !enrollmentcrypto.ValidHash(e.ApprovalDigest) {
			return State{}, ErrInvalid
		}
		next.ApprovalDigest = e.ApprovalDigest
		next.Phase = ActivationStarted
	case FinishActivation:
		if current.Phase != ActivationStarted || !e.StoppedAndDisabled || !e.ActivatedIdentity || e.ApprovalDigest != current.ApprovalDigest || !enrollmentcrypto.ValidHash(e.IdentityDigest) {
			return State{}, ErrInvalid
		}
		next.IdentityDigest = e.IdentityDigest
		next.Phase = IdentityActive
	case BeginGrants:
		if current.Phase != IdentityActive || !e.StoppedAndDisabled || !e.ActivatedIdentity || e.ApprovalDigest != current.ApprovalDigest || e.IdentityDigest != current.IdentityDigest {
			return State{}, ErrInvalid
		}
		next.Phase = GrantsStarted
	case FinishGrants:
		if current.Phase != GrantsStarted || !e.StoppedAndDisabled || !e.ActivatedIdentity || e.ApprovalDigest != current.ApprovalDigest || e.IdentityDigest != current.IdentityDigest || !validGrants(current.Consent, e.GrantDigests) {
			return State{}, ErrInvalid
		}
		next.GrantDigests = append([]lanclient.WindowsCapabilityGrantDigest(nil), e.GrantDigests...)
		next.Phase = GrantsVerified
	case BeginStartup:
		if current.Phase != GrantsVerified || !e.StoppedAndDisabled || !e.ActivatedIdentity || e.ApprovalDigest != current.ApprovalDigest || e.IdentityDigest != current.IdentityDigest || !reflect.DeepEqual(e.GrantDigests, current.GrantDigests) {
			return State{}, ErrInvalid
		}
		next.Phase = StartupStarted
	case FinishStartup:
		if current.Phase != StartupStarted || !e.ActivatedIdentity || !e.ServiceRunning || !e.StartupAutomaticVerified || e.ApprovalDigest != current.ApprovalDigest || e.IdentityDigest != current.IdentityDigest || !reflect.DeepEqual(e.GrantDigests, current.GrantDigests) {
			return State{}, ErrInvalid
		}
		next.Phase = Completed
	default:
		return State{}, ErrInvalid
	}
	next.UpdatedAt = at
	if !validState(next) {
		return State{}, ErrInvalid
	}
	return next, nil
}
