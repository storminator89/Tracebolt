package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"net/http"
	"runtime"
	"strconv"
	"time"
)

const WindowsEnrollmentPathPrefix = "/v2/windows/enrollment/"

type wireClient struct {
	client            *http.Client
	origin            string
	collectionProfile string
}
type httpFailure struct {
	status                 int
	retryAfter             time.Duration
	definiteClaimRejection bool
}

func (*httpFailure) Error() string { return "enrollment manager did not accept the bounded request" }
func retryable(e error) bool {
	if errors.Is(e, ErrTransport) {
		return true
	}
	var f *httpFailure
	return errors.As(e, &f) && (f.status == 429 || f.status == 503 || f.status == 401 || f.status == 409)
}
func retryDelay(e error, d time.Duration) time.Duration {
	var f *httpFailure
	if errors.As(e, &f) && f.retryAfter > d {
		return f.retryAfter
	}
	return d
}
func (w *wireClient) post(ctx context.Context, path string, raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > enrollmentcrypto.MaxClaimBytes {
		return nil, ErrResponse
	}
	// The caller selects only fixed protocol verbs; bootstrap data cannot supply a path.
	switch path {
	case "challenge", "claim", "status", "credential", "activate":
	default:
		return nil, ErrResponse
	}
	prefix := "/v2/enrollment/"
	if w.collectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
		prefix = WindowsEnrollmentPathPrefix
	}
	req, e := http.NewRequestWithContext(ctx, "POST", w.origin+prefix+path, bytes.NewReader(raw))
	if e != nil {
		return nil, ErrTransport
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, e := w.client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrTransport
	}
	defer res.Body.Close()
	if len(res.Header.Values("Content-Type")) != 1 || (res.Header.Get("Content-Type") != "application/json" && res.Header.Get("Content-Type") != "application/json; charset=utf-8") || len(res.Header.Values("Content-Encoding")) != 0 || res.Uncompressed || res.ContentLength > maxJSON {
		return nil, ErrResponse
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, maxJSON+1))
	if e != nil {
		return nil, ErrTransport
	}
	if len(body) > maxJSON {
		return nil, ErrResponse
	}
	if res.StatusCode != http.StatusOK {
		f := &httpFailure{status: res.StatusCode}
		var failure struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if len(body) <= 1024 && strictJSON(body, &failure) == nil {
			f.definiteClaimRejection = res.StatusCode == 401 && failure.Error.Code == "enrollment_proof_rejected" && failure.Error.Message == "Enrollment proof is invalid or expired." || res.StatusCode == 400 && failure.Error.Code == "invalid_enrollment_request" && failure.Error.Message == "Enrollment request is invalid or unsupported."
		}
		if res.StatusCode == 429 {
			f.retryAfter = time.Minute
		}
		if v, e := strconv.Atoi(res.Header.Get("Retry-After")); e == nil && v > 0 && v <= 300 {
			f.retryAfter = time.Duration(v) * time.Second
		}
		return nil, f
	}
	return body, nil
}

type challengeEnvelope struct {
	SchemaVersion string                            `json:"schemaVersion"`
	Context       enrollmentcrypto.ChallengeContext `json:"context"`
	Purpose       string                            `json:"purpose"`
	ServerNow     string                            `json:"serverNow"`
}

func (s *session) challenge(ctx context.Context, purpose string) (enrollmentcrypto.ChallengeContext, error) {
	raw, _ := json.Marshal(struct {
		InvitationID string `json:"invitationId"`
		ClaimID      string `json:"claimId"`
		Purpose      string `json:"purpose"`
	}{s.l.Bootstrap.InvitationID, s.l.ClaimID, purpose})
	body, e := s.wire.post(ctx, "challenge", raw)
	if e != nil {
		return enrollmentcrypto.ChallengeContext{}, e
	}
	var in challengeEnvelope
	if strictJSON(body, &in) != nil {
		return enrollmentcrypto.ChallengeContext{}, ErrResponse
	}
	c, b := in.Context, s.l.Bootstrap
	now := time.Now()
	serverNow, e := time.Parse(time.RFC3339Nano, in.ServerNow)
	if e != nil || serverNow.Before(now.Add(-time.Minute)) || serverNow.After(now.Add(time.Minute)) || in.SchemaVersion != "tracebolt.enrollment-challenge.v2" || in.Purpose != purpose || c.ManagerInstanceID != b.ManagerInstanceID || c.Profile != b.Profile || c.Origin != b.EnrollmentOrigin || c.CollectionProfile != b.CollectionProfile || c.InvitationID != b.InvitationID || c.ClaimID != s.l.ClaimID || c.ExpiresAt <= now.Unix() || c.ExpiresAt > now.Add(90*time.Second).Unix() {
		return enrollmentcrypto.ChallengeContext{}, ErrResponse
	}
	nonce, e := base64.RawURLEncoding.Strict().DecodeString(c.Challenge)
	if e != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != c.Challenge {
		return enrollmentcrypto.ChallengeContext{}, ErrResponse
	}
	if err := s.enforceServiceDeadline(time.Now()); err != nil {
		return enrollmentcrypto.ChallengeContext{}, err
	}
	return c, nil
}
func proofBase(c enrollmentcrypto.ChallengeContext) map[string]string {
	return map[string]string{"managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "challenge": c.Challenge}
}
func (s *session) statusBytes(ctx context.Context, purpose, requestID string) ([]byte, error) {
	c, e := s.challenge(ctx, purpose)
	if e != nil {
		return nil, e
	}
	message, e := enrollmentcrypto.StatusSigningMessage(c, purpose, requestID, s.publicDER, time.Now())
	if e != nil {
		return nil, ErrResponse
	}
	fields := proofBase(c)
	fields["schemaVersion"] = enrollmentcrypto.StatusVersion
	fields["keyFingerprint"] = fingerprint(s.publicDER)
	fields["requestId"] = requestID
	fields["purpose"] = purpose
	fields["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.key, message))
	return json.Marshal(fields)
}
func (s *session) status(ctx context.Context) (enrollmentstate.Snapshot, error) {
	raw, e := s.statusBytes(ctx, "status", s.l.StatusRequestID)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	body, e := s.wire.post(ctx, "status", raw)
	if e != nil {
		return enrollmentstate.Snapshot{}, e
	}
	snap, e := enrollmentstate.DecodeSnapshot(body)
	if e != nil {
		return enrollmentstate.Snapshot{}, ErrResponse
	}
	return snap, nil
}
func (s *session) claim(ctx context.Context) error {
	if s.opts.Secret == nil {
		return ErrInput
	}
	secret, e := s.opts.Secret(ctx)
	if e != nil {
		clear(secret)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInput
	}
	defer clear(secret)
	if len(secret) != 43 {
		return ErrInput
	}
	if _, e = enrollmentcrypto.InvitationHash(string(secret)); e != nil {
		return ErrInput
	}
	c, e := s.challenge(ctx, "claim")
	if e != nil {
		return e
	}
	message, e := enrollmentcrypto.ClaimSigningMessage(c, s.l.ClaimRequestID, s.csr, string(secret), time.Now())
	if e != nil {
		return ErrResponse
	}
	defer clear(message)
	fields := proofBase(c)
	fields["schemaVersion"] = enrollmentcrypto.ClaimVersion
	fields["requestId"] = s.l.ClaimRequestID
	fields["invitationSecret"] = string(secret)
	fields["csr"] = s.l.CSR
	fields["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.key, message))
	raw, e := json.Marshal(fields)
	delete(fields, "invitationSecret")
	if e != nil {
		return ErrInput
	}
	defer clear(raw)
	verified, e := enrollmentcrypto.VerifyClaim(raw, c, time.Now())
	if e != nil {
		return ErrInput
	}
	if s.l.ClaimHash != "" && s.l.ClaimHash != verified.ClaimHash() && !(s.l.Bootstrap.Profile == "tls" && s.l.ClaimDefinitelyRejected) {
		return ErrInvitation
	}
	hadAmbiguity := s.l.AmbiguousClaimHash != ""
	s.l.ClaimHash = verified.ClaimHash()
	s.l.AmbiguousClaimHash = s.l.ClaimHash
	s.l.ClaimDefinitelyRejected = false
	// Includes the semantic claim hash, but never the invitation or claim bytes.
	if e = s.save(); e != nil {
		return e
	}
	body, e := s.wire.post(ctx, "claim", raw)
	if e != nil {
		var f *httpFailure
		if errors.As(e, &f) && (f.status == 401 || f.status == 400) {
			// Only authenticated TLS rejection can authorize correcting a
			// candidate. Retain its hash and force status reconciliation on
			// the next Run before any further prompt; HTTP cannot set this.
			if s.l.Bootstrap.Profile == "tls" && f.definiteClaimRejection && !hadAmbiguity {
				s.l.AmbiguousClaimHash = ""
				s.l.ClaimDefinitelyRejected = true
				if err := s.save(); err != nil {
					return err
				}
			}
			return ErrInvitation
		}
		return e
	}
	snapshot, e := enrollmentstate.DecodeSnapshot(body)
	if e != nil {
		return ErrResponse
	}
	return s.acceptSnapshot(snapshot)
}
func (s *session) acceptSnapshot(v enrollmentstate.Snapshot) error {
	b := s.l.Bootstrap
	if enrollmentstate.ValidateSnapshot(v) != nil || v.Binding.InstanceID != b.ManagerInstanceID || v.Binding.Profile != b.Profile || v.Binding.Origin != b.EnrollmentOrigin || v.Binding.CollectionProfile != b.CollectionProfile || v.Binding.IssuerFingerprint != fingerprint(s.issuerDER) || v.InvitationID != b.InvitationID || validatePlatformSnapshot(v, b, runtime.GOOS) != nil || v.Revision < s.l.LastRevision {
		return ErrResponse
	}
	if v.Claim.ClaimID != s.l.ClaimID || v.Claim.RequestID != s.l.ClaimRequestID || v.Claim.KeyFingerprint != fingerprint(s.publicDER) || v.Claim.CSRHash != fingerprint(s.csr) || s.l.ClaimHash == "" || v.Claim.ClaimHash != s.l.ClaimHash || v.Claim.ComparisonCode != s.trust.ComparisonCode {
		return ErrResponse
	}
	if s.l.CertificateDER != "" && v.State != enrollmentstate.Expired && v.State != enrollmentstate.Canceled && v.State != enrollmentstate.Rejected && v.State != enrollmentstate.Revoked {
		if s.matchIssuedSnapshot(v) != nil {
			return ErrResponse
		}
	}
	s.l.ClaimDefinitelyRejected = false
	s.l.AmbiguousClaimHash = ""
	s.l.ClaimConfirmed = true
	s.l.LastRevision = v.Revision
	return s.save()
}
func (s *session) verifyLocalIntent(i enrollmentcrypto.Intent) error {
	b := s.l.Bootstrap
	if enrollmentcrypto.ValidateIntent(i) != nil || i.ManagerInstanceID != b.ManagerInstanceID || i.Profile != b.Profile || i.Origin != b.EnrollmentOrigin || i.CollectionProfile != b.CollectionProfile || i.InvitationID != b.InvitationID || i.ClaimID != s.l.ClaimID || i.KeyFingerprint != fingerprint(s.publicDER) || i.PublicKeyDERBase64 != base64.RawStdEncoding.EncodeToString(s.publicDER) || i.CSRHash != fingerprint(s.csr) || i.ClaimHash != s.l.ClaimHash || i.IssuerFingerprint != fingerprint(s.issuerDER) {
		return ErrResponse
	}
	return nil
}
func (s *session) expectedIntent(v enrollmentstate.Snapshot) enrollmentcrypto.Intent {
	b := s.l.Bootstrap
	return enrollmentcrypto.Intent{ManagerInstanceID: b.ManagerInstanceID, Profile: b.Profile, Origin: b.EnrollmentOrigin, CollectionProfile: b.CollectionProfile, InvitationID: b.InvitationID, ClaimID: s.l.ClaimID, RequestID: v.Intent.RequestID, DeviceID: v.Intent.DeviceID, IntentID: v.Intent.IntentID, KeyFingerprint: fingerprint(s.publicDER), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(s.publicDER), CSRHash: fingerprint(s.csr), ClaimHash: s.l.ClaimHash, IssuerFingerprint: fingerprint(s.issuerDER), SerialHex: v.Intent.SerialHex, TemplateVersion: enrollmentcrypto.TemplateVersion, KeyGeneration: 1, NotBefore: v.Intent.NotBefore, NotAfter: v.Intent.NotAfter}
}
func (s *session) matchIssuedSnapshot(v enrollmentstate.Snapshot) error {
	if s.l.Intent != s.expectedIntent(v) || v.Approval.DeviceID != s.l.Intent.DeviceID {
		return ErrResponse
	}
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil || v.Issuance.CertificateHash != fingerprint(der) {
		return ErrResponse
	}
	return nil
}
func (s *session) credential(ctx context.Context, v enrollmentstate.Snapshot) error {
	raw, e := s.statusBytes(ctx, "credential", s.l.CredentialRequestID)
	if e != nil {
		return e
	}
	if err := s.enforceServiceDeadline(time.Now()); err != nil {
		return err
	}
	body, e := s.wire.post(ctx, "credential", raw)
	if e != nil {
		return e
	}
	if err := s.enforceServiceDeadline(time.Now()); err != nil {
		return err
	}
	var in struct {
		SchemaVersion  string                  `json:"schemaVersion"`
		CertificateDER string                  `json:"certificateDer"`
		IssuerDER      string                  `json:"issuerDer"`
		Intent         enrollmentcrypto.Intent `json:"intent"`
	}
	if strictJSON(body, &in) != nil || in.SchemaVersion != "tracebolt.enrollment-credential.v2" || in.Intent != s.expectedIntent(v) || s.verifyLocalIntent(in.Intent) != nil {
		return ErrResponse
	}
	issuer, e := decode64(in.IssuerDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil || !bytes.Equal(issuer, s.issuerDER) {
		return ErrResponse
	}
	der, e := decode64(in.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil || fingerprint(der) != v.Issuance.CertificateHash {
		return ErrResponse
	}
	if _, e = enrollmentcrypto.VerifyIssued(der, s.issuerDER, in.Intent, time.Now()); e != nil {
		return ErrResponse
	}
	s.l.Intent = in.Intent
	s.l.CertificateDER = in.CertificateDER
	return s.save()
}
func (s *session) activate(ctx context.Context) error {
	c, e := s.challenge(ctx, "activation")
	if e != nil {
		return e
	}
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		return ErrState
	}
	message, e := enrollmentcrypto.ActivationSigningMessage(c, s.l.Intent, s.l.ActivationRequestID, fingerprint(der), time.Now())
	if e != nil {
		return ErrResponse
	}
	fields := map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile, "origin": c.Origin, "deviceId": s.l.Intent.DeviceID, "intentId": s.l.Intent.IntentID, "certificateHash": fingerprint(der), "requestId": s.l.ActivationRequestID, "challenge": c.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.key, message))}
	raw, _ := json.Marshal(fields)
	s.l.ActivationAttempted = true
	if e = s.save(); e != nil {
		return e
	}
	if err := s.enforceServiceDeadline(time.Now()); err != nil {
		return err
	}
	body, e := s.wire.post(ctx, "activate", raw)
	if e != nil {
		return e
	}
	if err := s.enforceServiceDeadline(time.Now()); err != nil {
		return err
	}
	v, e := enrollmentstate.DecodeSnapshot(body)
	if e != nil || v.State != enrollmentstate.Activated || v.Activation.RequestID != s.l.ActivationRequestID {
		return ErrResponse
	}
	return s.acceptSnapshot(v)
}
