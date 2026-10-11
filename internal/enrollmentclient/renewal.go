package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/renewalidentity"
	"os"
	"time"
)

const renewalTransactionVersion = "tracebolt.renewal-transaction.v1"

// Initial attempts are spread over fifteen minutes inside the 48-hour window.
func renewalDue(m renewalidentity.Manifest) time.Time {
	jitter := time.Duration(m.CertificateDER[len(m.CertificateDER)-1]%16) * time.Minute
	return time.Unix(m.Intent.NotAfter, 0).Add(-48*time.Hour + jitter)
}

func (s *session) renewalClock() time.Time {
	if s.renewalNow != nil {
		return s.renewalNow()
	}
	return time.Now()
}

// The durable transaction is written before any issue/activation request. It
// retains the exact candidate across lost replies; no new key or request is
// generated to resolve an uncertain signing outcome.
type renewalTransaction struct {
	Version               string             `json:"version"`
	IdentityGeneration    string             `json:"identityGeneration"`
	PredecessorGeneration uint64             `json:"predecessorGeneration"`
	RequestID             string             `json:"requestId"`
	StatusRequestID       string             `json:"statusRequestId"`
	ActivationRequestID   string             `json:"activationRequestId"`
	Phase                 string             `json:"phase"`
	Candidate             *renewalCredential `json:"candidate,omitempty"`
	LastRevision          uint64             `json:"lastRevision"`
	LastServerNow         int64              `json:"lastServerNow"`
	NextAttemptAt         int64              `json:"nextAttemptAt"`
	Failures              uint64             `json:"failures"`
	State                 string             `json:"state"`
}

type renewalCredential struct {
	CertificateDER       string                  `json:"certificateDer"`
	Intent               enrollmentcrypto.Intent `json:"intent"`
	CertificateHash      string                  `json:"certificateHash"`
	CredentialGeneration uint64                  `json:"credentialGeneration"`
	RequestID            string                  `json:"requestId"`
}

type renewalEnvelope struct {
	SchemaVersion        string             `json:"schemaVersion"`
	IdentityGeneration   string             `json:"identityGeneration"`
	CredentialGeneration uint64             `json:"credentialGeneration"`
	Revision             uint64             `json:"revision"`
	Enabled              bool               `json:"enabled"`
	AuthorityExpiresAt   int64              `json:"authorityExpiresAt"`
	Status               string             `json:"status"`
	Current              renewalCredential  `json:"current"`
	Candidate            *renewalCredential `json:"candidate,omitempty"`
	ServerNow            time.Time          `json:"serverNow"`
}

type renewalChallenge struct {
	SchemaVersion string                          `json:"schemaVersion"`
	Context       enrollmentcrypto.RenewalContext `json:"context"`
	ServerNow     string                          `json:"serverNow"`
}

// time.Time's wire representation is a string, not a reflected object. Keep a
// strict string envelope so all wire fields retain duplicate/null rejection.
type renewalEnvelopeWire struct {
	SchemaVersion        string             `json:"schemaVersion"`
	IdentityGeneration   string             `json:"identityGeneration"`
	CredentialGeneration uint64             `json:"credentialGeneration"`
	Revision             uint64             `json:"revision"`
	Enabled              bool               `json:"enabled"`
	AuthorityExpiresAt   int64              `json:"authorityExpiresAt"`
	Status               string             `json:"status"`
	Current              renewalCredential  `json:"current"`
	Candidate            *renewalCredential `json:"candidate,omitempty"`
	ServerNow            string             `json:"serverNow"`
}

func (s *session) initialRenewalManifest() (renewalidentity.Manifest, error) {
	b := s.l.Bootstrap
	if b.RenewalPolicy != renewalidentity.Policy || b.Profile != "tls" || !s.l.Activated || s.l.LastRevision == 0 {
		return renewalidentity.Manifest{}, ErrState
	}
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		return renewalidentity.Manifest{}, ErrState
	}
	issuer, e := x509.ParseCertificate(s.issuerDER)
	if e != nil {
		return renewalidentity.Manifest{}, ErrState
	}
	identity, e := enrollmentcrypto.RenewalIdentityGeneration(s.l.Intent)
	if e != nil {
		return renewalidentity.Manifest{}, ErrState
	}
	return renewalidentity.Manifest{Version: renewalidentity.Version, ManagerInstanceID: b.ManagerInstanceID, EnrollmentOrigin: b.EnrollmentOrigin, AgentOrigin: b.AgentOrigin, CollectionProfile: b.CollectionProfile, DeviceID: s.l.Intent.DeviceID, IdentityGeneration: identity, KeyFingerprint: fingerprint(s.publicDER), AnchorHash: fingerprint(der), IssuerFingerprint: fingerprint(s.issuerDER), AuthorityExpiresAt: issuer.NotAfter.Unix(), CredentialGeneration: 1, Revision: s.l.LastRevision, CertificateDER: der, AnchorIntent: s.l.Intent, Intent: s.l.Intent, LastServerNow: s.l.Intent.NotBefore}, nil
}

func (s *session) validateRenewalManifest(m renewalidentity.Manifest, now time.Time) error {
	return s.validateRenewalManifestAt(m, now, false)
}
func (s *session) validateRenewalManifestAt(m renewalidentity.Manifest, now time.Time, allowExpired bool) error {
	expected, e := s.initialRenewalManifest()
	if e != nil {
		return e
	}
	if m.Version != expected.Version || m.ManagerInstanceID != expected.ManagerInstanceID || m.EnrollmentOrigin != expected.EnrollmentOrigin || m.AgentOrigin != expected.AgentOrigin || m.CollectionProfile != expected.CollectionProfile || m.DeviceID != expected.DeviceID || m.IdentityGeneration != expected.IdentityGeneration || m.KeyFingerprint != expected.KeyFingerprint || m.AnchorHash != expected.AnchorHash || m.IssuerFingerprint != expected.IssuerFingerprint || m.AuthorityExpiresAt != expected.AuthorityExpiresAt || m.AnchorIntent != expected.AnchorIntent || m.Revision < expected.Revision {
		return ErrState
	}
	anchor, e := x509.ParseCertificate(expected.CertificateDER)
	if e != nil {
		return ErrState
	}
	issuer, e := x509.ParseCertificate(s.issuerDER)
	if e != nil {
		return ErrState
	}
	if allowExpired && now.Unix() >= m.Intent.NotAfter {
		if now.Unix() < m.LastServerNow || now.Unix() >= m.AuthorityExpiresAt {
			return ErrState
		}
		now = time.Unix(max(m.LastServerNow, m.Intent.NotBefore), 0)
	}
	if _, e = m.Validate(anchor, issuer, m.AgentOrigin, m.CollectionProfile, m.DeviceID, now); e != nil {
		return ErrState
	}
	return nil
}
func (s *session) loadRenewalManifest() (renewalidentity.Manifest, error) {
	raw, e := s.store.Read(renewalidentity.ManifestName)
	if e != nil {
		return renewalidentity.Manifest{}, ErrState
	}
	m, e := renewalidentity.Parse(raw)
	if e != nil || s.validateRenewalManifest(m, s.renewalClock()) != nil {
		return renewalidentity.Manifest{}, ErrState
	}
	return m, nil
}
func initialRenewalTransaction(m renewalidentity.Manifest) renewalTransaction {
	return renewalTransaction{Version: renewalTransactionVersion, IdentityGeneration: m.IdentityGeneration, PredecessorGeneration: m.CredentialGeneration, Phase: "idle", LastRevision: m.Revision, LastServerNow: m.LastServerNow, State: "healthy"}
}
func (s *session) saveRenewalTransaction(t renewalTransaction) error {
	raw, e := json.Marshal(t)
	if e != nil {
		return ErrState
	}
	return s.store.Write(renewalidentity.LedgerName, raw)
}
func (s *session) prepareRenewal() error {
	expected, e := s.initialRenewalManifest()
	if e != nil {
		return e
	}
	raw, e := s.store.Read(renewalidentity.ManifestName)
	if e == nil {
		m, e := renewalidentity.Parse(raw)
		if e != nil || s.validateRenewalManifest(m, s.renewalClock()) != nil {
			return ErrState
		}
		_, e = s.loadRenewalTransaction(m)
		return e
	}
	if !errors.Is(e, os.ErrNotExist) || s.l.SenderInitializationStarted {
		return ErrState
	}
	// A retained partial initial transaction must match byte-for-byte; it cannot
	// be reused to adopt another identity or to initialize a used store again.
	tx := initialRenewalTransaction(expected)
	want, e := json.Marshal(tx)
	if e != nil {
		return ErrState
	}
	old, e := s.store.Read(renewalidentity.LedgerName)
	if errors.Is(e, os.ErrNotExist) {
		if e = s.store.Write(renewalidentity.LedgerName, want); e != nil {
			return e
		}
	} else if e != nil || !bytes.Equal(old, want) {
		return ErrState
	}
	raw, e = json.Marshal(expected)
	if e != nil {
		return ErrState
	}
	return s.store.Write(renewalidentity.ManifestName, raw)
}
func (s *session) loadRenewalTransaction(m renewalidentity.Manifest) (renewalTransaction, error) {
	var tx renewalTransaction
	raw, e := s.store.Read(renewalidentity.LedgerName)
	if e != nil || strictJSON(raw, &tx) != nil {
		return tx, ErrState
	}
	if tx.Version != renewalTransactionVersion || tx.IdentityGeneration != m.IdentityGeneration || tx.PredecessorGeneration == 0 || tx.LastRevision < m.Revision || tx.LastServerNow < m.LastServerNow || s.renewalClock().Unix() < tx.LastServerNow || tx.Failures > 32 || tx.NextAttemptAt < 0 {
		return tx, ErrState
	}
	switch tx.Phase {
	case "idle":
		if tx.PredecessorGeneration != m.CredentialGeneration || tx.RequestID != "" || tx.StatusRequestID != "" || tx.ActivationRequestID != "" || tx.Candidate != nil {
			return tx, ErrState
		}
	case "intent", "staged", "activating":
		for _, id := range []string{tx.RequestID, tx.StatusRequestID, tx.ActivationRequestID} {
			if !enrollmentcrypto.ValidID(id, "request_") {
				return tx, ErrState
			}
		}
		if tx.PredecessorGeneration != m.CredentialGeneration && (tx.PredecessorGeneration+1 != m.CredentialGeneration || tx.Candidate == nil || tx.Candidate.CertificateHash != fingerprint(m.CertificateDER)) {
			return tx, ErrState
		}
		if tx.Phase != "intent" && tx.Candidate == nil {
			return tx, ErrState
		}
	default:
		return tx, ErrState
	}
	switch tx.State {
	case "healthy", "due", "retrying", "blocked", "expired", "revoked":
	default:
		return tx, ErrState
	}
	return tx, nil
}

func (s *session) renewalProof(ctx context.Context, m renewalidentity.Manifest, tx *renewalTransaction, credential renewalCredential, purpose, requestID string) ([]byte, error) {
	raw, _ := json.Marshal(struct {
		InvitationID    string `json:"invitationId"`
		ClaimID         string `json:"claimId"`
		CertificateHash string `json:"certificateHash"`
		Purpose         string `json:"purpose"`
	}{s.l.Bootstrap.InvitationID, s.l.ClaimID, credential.CertificateHash, purpose})
	body, e := s.wire.post(ctx, "renewal/challenge", raw)
	if e != nil {
		return nil, e
	}
	var in renewalChallenge
	if strictJSON(body, &in) != nil {
		return nil, ErrResponse
	}
	c := in.Context
	at, e := time.Parse(time.RFC3339Nano, in.ServerNow)
	now := s.renewalClock()
	if e != nil || in.SchemaVersion != "tracebolt.enrollment-renewal-challenge.v1" || at.Unix() < tx.LastServerNow || at.Before(now.Add(-time.Minute)) || at.After(now.Add(time.Minute)) || c.ManagerInstanceID != m.ManagerInstanceID || c.Profile != "tls" || c.Origin != m.EnrollmentOrigin || c.AgentOrigin != m.AgentOrigin || c.CollectionProfile != m.CollectionProfile || c.InvitationID != s.l.Bootstrap.InvitationID || c.ClaimID != s.l.ClaimID || c.RenewalPolicy != renewalidentity.Policy || c.IdentityGeneration != m.IdentityGeneration || c.DeviceID != m.DeviceID || c.KeyFingerprint != m.KeyFingerprint || c.CertificateHash != credential.CertificateHash || c.CredentialGeneration != credential.CredentialGeneration || c.Revision < tx.LastRevision || c.Purpose != purpose {
		return nil, ErrResponse
	}
	message, e := enrollmentcrypto.RenewalSigningMessage(c, requestID, now)
	if e != nil {
		return nil, ErrResponse
	}
	// Record accepted authority floors before the signed mutation can be sent.
	tx.LastRevision = c.Revision
	tx.LastServerNow = at.Unix()
	if e = s.saveRenewalTransaction(*tx); e != nil {
		return nil, e
	}
	return enrollmentcrypto.RenewalProofJSON(c, requestID, ed25519.Sign(s.key, message))
}
func manifestCredential(m renewalidentity.Manifest) renewalCredential {
	return renewalCredential{CertificateDER: base64.RawStdEncoding.EncodeToString(m.CertificateDER), Intent: m.Intent, CertificateHash: fingerprint(m.CertificateDER), CredentialGeneration: m.CredentialGeneration, RequestID: m.Intent.RequestID}
}
func sameCredential(a, b renewalCredential) bool {
	return a.CertificateDER == b.CertificateDER && a.Intent == b.Intent && a.CertificateHash == b.CertificateHash && a.CredentialGeneration == b.CredentialGeneration
}
func (s *session) renewalRequest(ctx context.Context, m renewalidentity.Manifest, tx *renewalTransaction, credential renewalCredential, path, purpose, requestID string) (renewalEnvelope, error) {
	proof, e := s.renewalProof(ctx, m, tx, credential, purpose, requestID)
	if e != nil {
		return renewalEnvelope{}, e
	}
	body, e := s.wire.post(ctx, "renewal/"+path, proof)
	if e != nil {
		return renewalEnvelope{}, e
	}
	var in renewalEnvelopeWire
	if strictJSON(body, &in) != nil {
		return renewalEnvelope{}, ErrResponse
	}
	at, e := time.Parse(time.RFC3339Nano, in.ServerNow)
	now := s.renewalClock()
	if e != nil || in.SchemaVersion != enrollmentcrypto.RenewalVersion || in.IdentityGeneration != m.IdentityGeneration || in.AuthorityExpiresAt != m.AuthorityExpiresAt || in.Revision < tx.LastRevision || at.Unix() < tx.LastServerNow || at.Before(now.Add(-time.Minute)) || at.After(now.Add(time.Minute)) || in.CredentialGeneration != in.Current.CredentialGeneration {
		return renewalEnvelope{}, ErrResponse
	}
	switch in.Status {
	case "healthy", "due", "retrying", "blocked", "expired", "revoked":
	default:
		return renewalEnvelope{}, ErrResponse
	}
	tx.LastRevision = in.Revision
	tx.LastServerNow = at.Unix()
	tx.State = in.Status
	if e = s.saveRenewalTransaction(*tx); e != nil {
		return renewalEnvelope{}, e
	}
	return renewalEnvelope{in.SchemaVersion, in.IdentityGeneration, in.CredentialGeneration, in.Revision, in.Enabled, in.AuthorityExpiresAt, in.Status, in.Current, in.Candidate, at}, nil
}
func (s *session) candidateManifest(m renewalidentity.Manifest, c renewalCredential, revision uint64, at int64) (renewalidentity.Manifest, error) {
	if c.CredentialGeneration != m.CredentialGeneration+1 || c.CertificateHash == fingerprint(m.CertificateDER) || c.Intent.NotAfter <= m.Intent.NotAfter {
		return renewalidentity.Manifest{}, ErrResponse
	}
	der, e := decode64(c.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil || fingerprint(der) != c.CertificateHash {
		return renewalidentity.Manifest{}, ErrResponse
	}
	next := m
	next.CertificateDER = der
	next.Intent = c.Intent
	next.CredentialGeneration = c.CredentialGeneration
	next.Revision = revision
	next.LastServerNow = at
	if s.validateRenewalManifest(next, s.renewalClock()) != nil {
		return renewalidentity.Manifest{}, ErrResponse
	}
	return next, nil
}
func (s *session) publishRenewal(m renewalidentity.Manifest, tx *renewalTransaction, view renewalEnvelope) error {
	if tx.Candidate == nil || !sameCredential(view.Current, *tx.Candidate) {
		return ErrResponse
	}
	next, e := s.candidateManifest(m, view.Current, view.Revision, view.ServerNow.Unix())
	if e != nil {
		return e
	}
	raw, e := json.Marshal(next)
	if e != nil {
		return ErrState
	}
	// The sole active-generation commit. Old cert/ready/config/grant/sender files
	// stay exact, and all sender/helper activity is joined before this call.
	if e = s.store.Write(renewalidentity.ManifestName, raw); e != nil {
		return e
	}
	*tx = initialRenewalTransaction(next)
	return s.saveRenewalTransaction(*tx)
}

func (s *session) renewOnce(ctx context.Context, m renewalidentity.Manifest, tx *renewalTransaction) error {
	return s.renewOncePrepared(ctx, m, tx, true)
}
func (s *session) renewOncePrepared(ctx context.Context, m renewalidentity.Manifest, tx *renewalTransaction, activate bool) error {
	if tx.PredecessorGeneration+1 == m.CredentialGeneration {
		// The atomic manifest was published; a lost local journal commit may only
		// finish the already committed generation, never issue or activate again.
		if tx.Candidate == nil || !sameCredential(manifestCredential(m), *tx.Candidate) {
			return ErrState
		}
		*tx = initialRenewalTransaction(m)
		return s.saveRenewalTransaction(*tx)
	}
	now := s.renewalClock()
	if now.Unix() < tx.LastServerNow {
		return ErrState
	}
	if tx.State == "revoked" {
		return ErrTerminal
	}
	if tx.Phase == "idle" {
		if now.Unix() < tx.NextAttemptAt || now.Before(renewalDue(m)) {
			return nil
		}
		var e error
		tx.Phase = "intent"
		tx.State = "due"
		for _, id := range []*string{&tx.RequestID, &tx.StatusRequestID, &tx.ActivationRequestID} {
			*id, e = randomID("request_")
			if e != nil {
				return e
			}
		}
		if e = s.saveRenewalTransaction(*tx); e != nil {
			return e
		}
	}
	current := manifestCredential(m)
	auth := current
	if tx.Candidate != nil {
		auth = *tx.Candidate
	}
	view, e := s.renewalRequest(ctx, m, tx, auth, "status", enrollmentcrypto.PurposeRenewalStatus, tx.StatusRequestID)
	if e != nil {
		return e
	}
	if view.Status == "revoked" {
		return ErrTerminal
	}
	if tx.Candidate != nil && sameCredential(view.Current, *tx.Candidate) {
		if !activate {
			return errRenewalCutover
		}
		return s.publishRenewal(m, tx, view)
	}
	if !sameCredential(view.Current, current) {
		return ErrResponse
	}
	if !view.Enabled || view.Status == "blocked" {
		return ErrTerminal
	}
	if view.Status == "expired" || !s.renewalClock().Before(time.Unix(m.Intent.NotAfter, 0)) {
		return ErrTerminal
	}
	if view.Candidate == nil {
		if tx.Candidate != nil {
			return ErrResponse
		}
		view, e = s.renewalRequest(ctx, m, tx, current, "issue", enrollmentcrypto.PurposeRenewalIssue, tx.RequestID)
		if e != nil {
			return e
		}
	}
	if view.Candidate == nil || view.Candidate.RequestID != tx.RequestID {
		return ErrResponse
	}
	if _, e = s.candidateManifest(m, *view.Candidate, view.Revision, view.ServerNow.Unix()); e != nil {
		return e
	}
	if tx.Candidate != nil && !sameCredential(*tx.Candidate, *view.Candidate) {
		return ErrResponse
	}
	tx.Candidate = view.Candidate
	tx.Phase = "staged"
	if e = s.saveRenewalTransaction(*tx); e != nil {
		return e
	}
	if !activate {
		return errRenewalCutover
	}
	tx.Phase = "activating"
	if e = s.saveRenewalTransaction(*tx); e != nil {
		return e
	}
	view, e = s.renewalRequest(ctx, m, tx, *tx.Candidate, "activate", enrollmentcrypto.PurposeRenewalActivate, tx.ActivationRequestID)
	if e != nil {
		return e
	}
	return s.publishRenewal(m, tx, view)
}
