// Package enrollmentservice coordinates the durable enrollment state machine.
// It is an internal application service: HTTP authentication and transport guards
// belong to the caller. No constructor generates credentials or opens a listener.
package enrollmentservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"net/netip"
	"sync"
	"time"
)

const MaxRecords = 25
const MaxChallenges = 256
const challengeTTL = 60 * time.Second
const certificateTTL = 7 * 24 * time.Hour

var ErrConfiguration = errors.New("enrollment service configuration is invalid")
var ErrChallenge = errors.New("enrollment challenge is invalid or expired")
var ErrBusy = errors.New("enrollment service is temporarily busy")
var ErrPlatform = errors.New("enrollment platform is not available in this milestone")

// Signer must return the same fixed certificate for repeated identical intents.
// The initial integration uses enrollmentissuer's concrete Ed25519 signer only.
type Signer interface {
	Sign(context.Context, enrollmentcrypto.Intent, time.Time) (enrollmentcrypto.VerifiedCertificate, error)
	IssuerDER() []byte
	RootDER() []byte
	Fingerprint() string
}
type Service struct{ *serviceState }
type serviceState struct {
	store        *enrollmentstore.Store
	journal      *journalcache.Cache
	signer       Signer
	binding      enrollmentstate.Binding
	now          func() time.Time
	issuerExpiry time.Time
	issuerStart  time.Time
	mu           sync.Mutex
	challenges   map[string]challengeEntry
	peers        map[netip.Addr]peerWindow
	signing      chan struct{}
	proofs       chan struct{}
	global       peerWindow
}
type challengeEntry struct {
	context enrollmentcrypto.ChallengeContext
	purpose string
}
type peerWindow struct {
	start time.Time
	count int
}

func (Service) String() string               { return "enrollmentservice.Service{state:redacted}" }
func (Service) GoString() string             { return "enrollmentservice.Service{state:redacted}" }
func (s Service) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (Service) MarshalJSON() ([]byte, error) { return []byte(`{"stateRedacted":true}`), nil }

// New enforces the measured small-pilot retention cap. The clock is a trusted
// dependency; an HTTP request must never supply it. nil selects the real clock.
func New(store *enrollmentstore.Store, signer Signer, now func() time.Time) (*Service, error) {
	if store == nil || signer == nil {
		return nil, ErrConfiguration
	}
	cfg := store.Config()
	if cfg.RecordLimit < 1 || cfg.RecordLimit > MaxRecords {
		return nil, ErrConfiguration
	}
	cert, e := x509.ParseCertificate(signer.IssuerDER())
	if e != nil || signer.Fingerprint() != cfg.Binding.IssuerFingerprint {
		return nil, ErrConfiguration
	}
	if now == nil {
		now = time.Now
	}
	if !now().Before(cert.NotAfter) || now().Before(cert.NotBefore) {
		return nil, ErrConfiguration
	}
	return &Service{&serviceState{store: store, journal: journalcache.New(store, now), signer: signer, binding: cfg.Binding, now: now, issuerExpiry: cert.NotAfter, issuerStart: cert.NotBefore, challenges: make(map[string]challengeEntry), peers: make(map[netip.Addr]peerWindow), signing: make(chan struct{}, 1), proofs: make(chan struct{}, 2)}}, nil
}
func newID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrBusy
	}
	if b == ([16]byte{}) {
		return "", ErrBusy
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func newSecret() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrBusy
	}
	defer clear(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// InvitationCreation only exposes the one-time secret through Secret(). Generic
// formatting/JSON never discloses it. A lost response cannot recover this secret;
// the operator cancels that invitation and creates another.
type InvitationCreation struct{ value *invitationCreation }
type invitationCreation struct {
	snapshot enrollmentstate.Snapshot
	secret   string
}

func (v InvitationCreation) Snapshot() enrollmentstate.Snapshot {
	if v.value == nil {
		return enrollmentstate.Snapshot{}
	}
	return v.value.snapshot
}
func (v InvitationCreation) Secret() string {
	if v.value == nil {
		return ""
	}
	return v.value.secret
}
func (InvitationCreation) String() string {
	return "enrollmentservice.InvitationCreation{secret:redacted}"
}
func (InvitationCreation) GoString() string {
	return "enrollmentservice.InvitationCreation{secret:redacted}"
}
func (v InvitationCreation) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }
func (InvitationCreation) MarshalJSON() ([]byte, error) {
	return []byte(`{"secretRedacted":true}`), nil
}
func (s *Service) CreateInvitation(ctx context.Context, requestID, platform string) (InvitationCreation, error) {
	if s == nil || s.serviceState == nil || !enrollmentcrypto.ValidID(requestID, "request_") {
		return InvitationCreation{}, ErrConfiguration
	}
	// Linux retains its existing profile matrix. Windows admission is limited
	// to the existing basic scope over authenticated TLS; an invitation cannot
	// opt a Windows endpoint into the Linux managed collection profiles.
	if platform != "linux" && (platform != "windows" || s.binding.Profile != "tls" || s.binding.CollectionProfile != enrollmentcrypto.CollectionProfile) {
		return InvitationCreation{}, ErrPlatform
	}
	id, e := newID("invite_")
	if e != nil {
		return InvitationCreation{}, e
	}
	secret, e := newSecret()
	if e != nil {
		return InvitationCreation{}, e
	}
	verifier, e := enrollmentcrypto.InvitationHash(secret)
	if e != nil {
		return InvitationCreation{}, e
	}
	snapshot, e := s.store.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: id, RequestID: requestID, InvitationHash: hex.EncodeToString(verifier[:]), Platform: platform, Now: s.now().Unix()})
	if e != nil {
		return InvitationCreation{}, e
	}
	return InvitationCreation{value: &invitationCreation{snapshot: snapshot, secret: secret}}, nil
}

type Challenge struct {
	SchemaVersion string                            `json:"schemaVersion"`
	Context       enrollmentcrypto.ChallengeContext `json:"context"`
	Purpose       string                            `json:"purpose"`
	ServerNow     time.Time                         `json:"serverNow"`
}

// Challenge creates a bounded, expiring, one-use proof context. It intentionally
// does not disclose whether an invitation exists. peer is parsed RemoteAddr IP,
// never a forwarded header. Challenge loss/restart requires a new challenge.
func (s *Service) Challenge(peer, invitationID, claimID, purpose string) (Challenge, error) {
	if s == nil || s.serviceState == nil || !enrollmentcrypto.ValidID(invitationID, "invite_") || !enrollmentcrypto.ValidID(claimID, "claim_") || (purpose != "claim" && purpose != "status" && purpose != "credential" && purpose != "activation") {
		return Challenge{}, ErrChallenge
	}
	ip, e := netip.ParseAddr(peer)
	if e != nil || ip.Zone() != "" {
		return Challenge{}, ErrChallenge
	}
	ip = ip.Unmap()
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.challenges {
		if v.context.ExpiresAt <= now.Unix() {
			delete(s.challenges, k)
		}
	}
	for k, v := range s.peers {
		if now.Sub(v.start) >= time.Minute {
			delete(s.peers, k)
		}
	}
	if now.Before(s.global.start) {
		return Challenge{}, ErrBusy
	}
	if s.global.start.IsZero() || now.Sub(s.global.start) >= time.Minute {
		s.global = peerWindow{start: now}
	}
	if s.global.count >= 120 {
		return Challenge{}, ErrBusy
	}
	window, ok := s.peers[ip]
	if ok && (now.Before(window.start) || window.count >= 30) {
		return Challenge{}, ErrBusy
	}
	if !ok && len(s.peers) >= 256 || len(s.challenges) >= MaxChallenges {
		return Challenge{}, ErrBusy
	}
	if !ok {
		window.start = now
	}
	s.global.count++
	window.count++
	s.peers[ip] = window
	nonce, e := newSecret()
	if e != nil {
		return Challenge{}, e
	}
	c := enrollmentcrypto.ChallengeContext{ManagerInstanceID: s.binding.InstanceID, Profile: s.binding.Profile, Origin: s.binding.Origin, CollectionProfile: s.binding.CollectionProfile, InvitationID: invitationID, ClaimID: claimID, Challenge: nonce, ExpiresAt: now.Add(challengeTTL).Unix()}
	s.challenges[nonce] = challengeEntry{context: c, purpose: purpose}
	return Challenge{SchemaVersion: "tracebolt.enrollment-challenge.v2", Context: c, Purpose: purpose, ServerNow: now}, nil
}
func (s *Service) takeChallenge(nonce, purpose string) (enrollmentcrypto.ChallengeContext, error) {
	if s == nil || s.serviceState == nil {
		return enrollmentcrypto.ChallengeContext{}, ErrChallenge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.challenges[nonce]
	delete(s.challenges, nonce)
	now := s.now().Unix()
	if !ok || entry.purpose != purpose || now >= entry.context.ExpiresAt || entry.context.ExpiresAt > now+int64(challengeTTL/time.Second) {
		return enrollmentcrypto.ChallengeContext{}, ErrChallenge
	}
	return entry.context, nil
}
func (s *Service) Claim(ctx context.Context, nonce string, raw []byte) (enrollmentstate.Snapshot, error) {
	release, e := s.beginProof()
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	defer release()
	c, e := s.takeChallenge(nonce, "claim")
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	now := s.now().UTC()
	proof, e := enrollmentcrypto.VerifyClaim(raw, c, now)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	snapshot, e := s.store.Get(ctx, c.InvitationID)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	return s.store.Claim(ctx, enrollmentstate.ClaimCommand{Control: enrollmentstate.Control{InvitationID: c.InvitationID, RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, ClaimID: c.ClaimID}, proof)
}
func (s *Service) Approve(ctx context.Context, id, requestID, fingerprint string, revision uint64) (enrollmentstate.Snapshot, error) {
	current, e := s.store.Get(ctx, id)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	deviceID := current.Approval.DeviceID
	if deviceID == "" {
		deviceID, e = newID("agent_")
		if e != nil {
			return enrollmentstate.Snapshot{}, e
		}
	}
	return s.store.Approve(ctx, enrollmentstate.ApproveCommand{Control: enrollmentstate.Control{InvitationID: id, RequestID: requestID, ExpectedRevision: revision, Now: s.now().Unix()}, DeviceID: deviceID, KeyFingerprint: fingerprint})
}
func (s *Service) Terminate(ctx context.Context, id, requestID string, revision uint64, state enrollmentstate.State) (enrollmentstate.Snapshot, error) {
	return s.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: id, RequestID: requestID, ExpectedRevision: revision, Now: s.now().Unix()}, State: state})
}
func (s *Service) Snapshots(ctx context.Context) ([]enrollmentstate.Snapshot, error) {
	return s.store.Snapshots(ctx)
}
func (s *Service) statusProof(ctx context.Context, nonce, purpose string, raw []byte) (enrollmentcrypto.VerifiedStatus, error) {
	c, e := s.takeChallenge(nonce, purpose)
	if e != nil {
		return enrollmentcrypto.VerifiedStatus{}, e
	}
	_, key, e := s.store.StatusContext(ctx, c.InvitationID)
	if e != nil {
		return enrollmentcrypto.VerifiedStatus{}, e
	}
	proof, e := enrollmentcrypto.VerifyStatus(raw, key, c, s.now().UTC())
	if e != nil {
		return enrollmentcrypto.VerifiedStatus{}, e
	}
	if proof.Purpose() != purpose {
		return enrollmentcrypto.VerifiedStatus{}, enrollmentcrypto.ErrProof
	}
	return proof, nil
}
func (s *Service) Status(ctx context.Context, nonce string, raw []byte) (enrollmentstate.Snapshot, error) {
	release, e := s.beginProof()
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	defer release()
	proof, e := s.statusProof(ctx, nonce, "status", raw)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	snapshot, e := s.store.ReadStatus(ctx, proof.InvitationID(), proof, s.now().UTC())
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	if snapshot.State == enrollmentstate.Approved || snapshot.State == enrollmentstate.IssuanceIntent {
		if e = s.issue(ctx, snapshot.InvitationID); e != nil {
			return enrollmentstate.Snapshot{}, e
		}
		return s.store.ReadStatus(ctx, proof.InvitationID(), proof, s.now().UTC())
	}
	return snapshot, nil
}
func (s *Service) Credential(ctx context.Context, nonce string, raw []byte) ([]byte, error) {
	release, e := s.beginProof()
	if e != nil {
		return nil, e
	}
	defer release()
	proof, e := s.statusProof(ctx, nonce, "credential", raw)
	if e != nil {
		return nil, e
	}
	snapshot, e := s.store.Get(ctx, proof.InvitationID())
	if e != nil {
		return nil, e
	}
	return s.store.DeliverCredential(ctx, enrollmentstate.Control{InvitationID: proof.InvitationID(), RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: s.now().Unix()}, proof)
}
func (s *Service) Activate(ctx context.Context, nonce string, raw []byte) (enrollmentstate.Snapshot, error) {
	release, e := s.beginProof()
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	defer release()
	c, e := s.takeChallenge(nonce, "activation")
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	certificate, e := s.store.CertificateForVerification(ctx, c.InvitationID)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	proof, e := enrollmentcrypto.VerifyActivation(raw, certificate, c, s.now().UTC())
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	snapshot, e := s.store.Get(ctx, c.InvitationID)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	return s.store.Activate(ctx, enrollmentstate.Control{InvitationID: c.InvitationID, RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: s.now().Unix()}, proof)
}
func (s *Service) issue(ctx context.Context, id string) error {
	select {
	case s.signing <- struct{}{}:
		defer func() { <-s.signing }()
	default:
		return ErrBusy
	}
	snapshot, e := s.store.Get(ctx, id)
	if e != nil {
		return e
	}
	if snapshot.State == enrollmentstate.Issued || snapshot.State == enrollmentstate.Activated {
		return nil
	}
	if snapshot.State == enrollmentstate.Approved {
		request, e := newID("request_")
		if e != nil {
			return e
		}
		intent, e := newID("intent_")
		if e != nil {
			return e
		}
		serial, e := newID("")
		if e != nil {
			return e
		}
		now := s.now().UTC()
		start := now.Add(-30 * time.Second)
		if start.Before(s.issuerStart) {
			start = s.issuerStart
		}
		end := now.Add(certificateTTL)
		if !end.Before(s.issuerExpiry) {
			end = s.issuerExpiry.Add(-time.Second)
		}
		snapshot, e = s.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: enrollmentstate.Control{InvitationID: id, RequestID: request, ExpectedRevision: snapshot.Revision, Now: now.Unix()}, IntentID: intent, SerialHex: serial, TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: start.Unix(), NotAfter: end.Unix()})
		if e != nil {
			return e
		}
	}
	intent, e := s.store.SigningIntent(ctx, id, s.now().Unix())
	if e != nil {
		return e
	}
	certificate, e := s.signer.Sign(ctx, intent, s.now().UTC())
	if e != nil {
		return e
	}
	// This ID is stable after restart without retaining another secret or minting
	// another credential. It is distinct from the intent operation's request ID.
	digest := sha256.Sum256([]byte("Tracebolt issuance commit v2\x00" + intent.IntentID))
	request := "request_" + hex.EncodeToString(digest[:16])
	_, e = s.store.CommitIssued(ctx, enrollmentstate.Control{InvitationID: id, RequestID: request, ExpectedRevision: snapshot.Revision, Now: s.now().Unix()}, certificate)
	return e
}

// Binding is immutable public instance metadata, not a trust-discovery endpoint.
func (s *Service) Binding() enrollmentstate.Binding {
	if s == nil || s.serviceState == nil {
		return enrollmentstate.Binding{}
	}
	return s.binding
}
func (s *Service) IssuerDER() []byte {
	if s == nil || s.serviceState == nil {
		return nil
	}
	return s.signer.IssuerDER()
}

type CredentialEnvelope struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	CertificateDER string                  `json:"certificateDer"`
	IssuerDER      string                  `json:"issuerDer"`
	Intent         enrollmentcrypto.Intent `json:"intent"`
}

func (s *Service) CredentialEnvelope(ctx context.Context, nonce string, raw []byte) (CredentialEnvelope, error) {
	release, e := s.beginProof()
	if e != nil {
		return CredentialEnvelope{}, e
	}
	defer release()
	c, e := s.takeChallenge(nonce, "credential")
	if e != nil {
		return CredentialEnvelope{}, e
	}
	_, key, e := s.store.StatusContext(ctx, c.InvitationID)
	if e != nil {
		return CredentialEnvelope{}, e
	}
	proof, e := enrollmentcrypto.VerifyStatus(raw, key, c, s.now().UTC())
	if e != nil {
		return CredentialEnvelope{}, e
	}
	if proof.Purpose() != enrollmentcrypto.PurposeCredential {
		return CredentialEnvelope{}, enrollmentcrypto.ErrProof
	}
	snapshot, e := s.store.Get(ctx, proof.InvitationID())
	if e != nil {
		return CredentialEnvelope{}, e
	}
	// Obtain immutable public intent before the final transaction-bound delivery.
	cert, e := s.store.CertificateForVerification(ctx, proof.InvitationID())
	if e != nil {
		return CredentialEnvelope{}, e
	}
	der, e := s.store.DeliverCredential(ctx, enrollmentstate.Control{InvitationID: proof.InvitationID(), RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: s.now().Unix()}, proof)
	if e != nil {
		return CredentialEnvelope{}, e
	}
	return CredentialEnvelope{SchemaVersion: "tracebolt.enrollment-credential.v2", CertificateDER: base64.RawStdEncoding.EncodeToString(der), IssuerDER: base64.RawStdEncoding.EncodeToString(s.signer.IssuerDER()), Intent: cert.Intent()}, nil
}

func (s *Service) beginProof() (func(), error) {
	if s == nil || s.serviceState == nil {
		return nil, ErrConfiguration
	}
	select {
	case s.proofs <- struct{}{}:
		return func() { <-s.proofs }, nil
	default:
		return nil, ErrBusy
	}
}

func (s *Service) RootDER() []byte {
	if s == nil || s.serviceState == nil {
		return nil
	}
	return s.signer.RootDER()
}

// Now supplies the same trusted clock used by lifecycle and challenge decisions.
func (s *Service) Now() time.Time {
	if s == nil || s.serviceState == nil {
		return time.Time{}
	}
	return s.now().UTC()
}
