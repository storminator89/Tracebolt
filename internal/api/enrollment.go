package api

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EnrollmentBootstrap is public operator-supplied bootstrap material. It is
// delivered through the authenticated UI; native clients must validate/pin its
// explicit trust before sending an invitation, never discover trust over HTTP.
type EnrollmentBootstrap struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	EnrollmentOrigin  string `json:"enrollmentOrigin"`
	AgentOrigin       string `json:"agentOrigin"`
	CollectionProfile string `json:"collectionProfile"`
	InvitationID      string `json:"invitationId"`
	ServerCAPEM       string `json:"serverCaPem"`
	IssuerRootPEM     string `json:"issuerRootPem"`
	IssuerPEM         string `json:"issuerPem"`
}

func (h *operatorHandler) enrollmentOperator(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/enrollment" && r.Method == "GET" {
		serverNow := time.Now().UTC()
		items := []enrollmentstate.Snapshot{}
		platforms := []string{}
		if h.enrollment != nil {
			var e error
			serverNow = h.enrollment.Now()
			items, e = h.enrollment.Snapshots(r.Context())
			if e != nil {
				enrollmentOperatorError(w, e)
				return
			}
			platforms = []string{"linux"}
		}
		write(w, 200, map[string]any{"enabled": h.enrollment != nil, "schemaVersion": "tracebolt.enrollment-operator.v2", "platforms": platforms, "recordLimit": enrollmentservice.MaxRecords, "items": items, "serverNow": serverNow})
		return
	}
	if h.enrollment == nil {
		fail(w, 404, "enrollment_unavailable", "Enrollment is not configured.")
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	if r.URL.Path == "/api/enrollment/invitations" {
		var input struct {
			RequestID string `json:"requestId"`
			Platform  string `json:"platform"`
		}
		if !readObject(w, r, 1024, []string{"requestId", "platform"}, &input) {
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		created, e := h.enrollment.CreateInvitation(r.Context(), input.RequestID, input.Platform)
		release()
		if e != nil {
			enrollmentOperatorError(w, e)
			return
		}
		bootstrap := h.enrollmentBootstrap
		bootstrap.InvitationID = created.Snapshot().InvitationID
		write(w, 201, map[string]any{"schemaVersion": "tracebolt.enrollment-invitation.v2", "snapshot": created.Snapshot(), "invitationSecret": created.Secret(), "bootstrap": bootstrap, "serverNow": h.enrollment.Now()})
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "enrollment" || !enrollmentcrypto.ValidID(parts[3], "invite_") {
		fail(w, 404, "not_found", "Enrollment action is unavailable.")
		return
	}
	if parts[4] == "approve" {
		var input struct {
			RequestID              string `json:"requestId"`
			ExpectedRevision       uint64 `json:"expectedRevision"`
			ExpectedKeyFingerprint string `json:"expectedKeyFingerprint"`
		}
		if !readObject(w, r, 1024, []string{"requestId", "expectedRevision", "expectedKeyFingerprint"}, &input) {
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		snapshot, e := h.enrollment.Approve(r.Context(), parts[3], input.RequestID, input.ExpectedKeyFingerprint, input.ExpectedRevision)
		release()
		if e != nil {
			enrollmentOperatorError(w, e)
			return
		}
		write(w, 200, snapshot)
		return
	}
	if parts[4] == "terminate" {
		var input struct {
			RequestID        string                `json:"requestId"`
			ExpectedRevision uint64                `json:"expectedRevision"`
			Action           enrollmentstate.State `json:"action"`
		}
		if !readObject(w, r, 1024, []string{"requestId", "expectedRevision", "action"}, &input) {
			return
		}
		if input.Action != enrollmentstate.Canceled && input.Action != enrollmentstate.Rejected && input.Action != enrollmentstate.Revoked {
			fail(w, 400, "invalid_action", "Enrollment action is unsupported.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		snapshot, e := h.enrollment.Terminate(r.Context(), parts[3], input.RequestID, input.ExpectedRevision, input.Action)
		release()
		if e != nil {
			enrollmentOperatorError(w, e)
			return
		}
		write(w, 200, snapshot)
		return
	}
	fail(w, 404, "not_found", "Enrollment action is unavailable.")
}

// enrollmentClient is selected only after the operator listener's actual TLS,
// exact Host, path/framing and no-CORS guards. It never uses a browser session.
func (h *operatorHandler) enrollmentClient(w http.ResponseWriter, r *http.Request) {
	if h.enrollment == nil {
		fail(w, 404, "enrollment_unavailable", "Enrollment is not configured.")
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	for _, name := range []string{"Cookie", "Origin", "Authorization", "Proxy-Authorization", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "Content-Encoding", "X-CSRF-Token"} {
		if len(r.Header.Values(name)) > 0 {
			fail(w, 400, "invalid_client_headers", "Native enrollment does not accept browser or forwarded credentials.")
			return
		}
	}
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 0 {
		fail(w, 400, "invalid_client_framing", "A bounded JSON request is required.")
		return
	}
	if r.URL.Path == "/v2/enrollment/challenge" {
		var input struct {
			InvitationID string `json:"invitationId"`
			ClaimID      string `json:"claimId"`
			Purpose      string `json:"purpose"`
		}
		if !readObject(w, r, 1024, []string{"invitationId", "claimId", "purpose"}, &input) {
			return
		}
		peer, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			fail(w, 400, "invalid_peer", "Native peer is unavailable.")
			return
		}
		challenge, e := h.enrollment.Challenge(peer, input.InvitationID, input.ClaimID, input.Purpose)
		if e != nil {
			enrollmentError(w, e)
			return
		}
		write(w, 200, challenge)
		return
	}
	switch r.URL.Path {
	case "/v2/enrollment/claim", "/v2/enrollment/status", "/v2/enrollment/credential", "/v2/enrollment/activate":
	default:
		fail(w, 404, "not_found", "Enrollment route is unavailable.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, enrollmentcrypto.MaxClaimBytes)
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 413, "request_too_large", "Enrollment proof exceeds its size limit.")
		return
	}
	// This extraction does not authorize anything. The crypto verifier rejects
	// duplicate/unknown/null/non-string fields and checks exact context afterward.
	var envelope struct {
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Challenge) != 43 {
		fail(w, 400, "invalid_proof", "Enrollment proof is invalid.")
		return
	}
	var result any
	switch r.URL.Path {
	case "/v2/enrollment/claim":
		result, e = h.enrollment.Claim(r.Context(), envelope.Challenge, raw)
	case "/v2/enrollment/status":
		result, e = h.enrollment.Status(r.Context(), envelope.Challenge, raw)
	case "/v2/enrollment/credential":
		result, e = h.enrollment.CredentialEnvelope(r.Context(), envelope.Challenge, raw)
	case "/v2/enrollment/activate":
		result, e = h.enrollment.Activate(r.Context(), envelope.Challenge, raw)
	}
	if e != nil {
		enrollmentError(w, e)
		return
	}
	write(w, 200, result)
}
func enrollmentError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, enrollmentstate.ErrCapacity):
		fail(w, 409, "enrollment_capacity_reached", "Enrollment retention limit reached; existing identities are not automatically deleted or reset.")
	case errors.Is(e, enrollmentservice.ErrBusy):
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "enrollment_busy", "Enrollment is temporarily busy.")
	case errors.Is(e, enrollmentservice.ErrChallenge), errors.Is(e, enrollmentcrypto.ErrProof), errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentstate.ErrExpired), errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 401, "enrollment_proof_rejected", "Enrollment proof is invalid or expired.")
	case errors.Is(e, enrollmentstate.ErrConflict), errors.Is(e, enrollmentstate.ErrState):
		fail(w, 409, "enrollment_state_conflict", "Enrollment state changed; refresh before continuing.")
	case errors.Is(e, enrollmentcrypto.ErrContract), errors.Is(e, enrollmentstate.ErrInvalid), errors.Is(e, enrollmentservice.ErrPlatform):
		fail(w, 400, "invalid_enrollment_request", "Enrollment request is invalid or unsupported.")
	case errors.Is(e, enrollmentstore.ErrStorage), errors.Is(e, enrollmentissuer.ErrConfiguration), errors.Is(e, enrollmentissuer.ErrSigning):
		fail(w, 503, "enrollment_unavailable", "Enrollment is temporarily unavailable.")
	default:
		fail(w, 503, "enrollment_unavailable", "Enrollment is temporarily unavailable.")
	}
}

func validEnrollmentBootstrap(service *enrollmentservice.Service, b EnrollmentBootstrap, origin string, httpTest bool) bool {
	binding := service.Binding()
	profile := "tls"
	if httpTest {
		profile = "http-test"
	}
	if b.SchemaVersion != "tracebolt.enrollment-bootstrap.v2" || b.ManagerInstanceID != binding.InstanceID || b.Profile != profile || b.Profile != binding.Profile || b.EnrollmentOrigin != origin || binding.Origin != origin || b.CollectionProfile != binding.CollectionProfile || b.InvitationID != "" {
		return false
	}
	u, e := url.Parse(b.AgentOrigin)
	scheme := "https"
	if httpTest {
		scheme = "http"
	}
	if e != nil || u.Scheme != scheme || u.Host == "" || b.AgentOrigin != scheme+"://"+u.Host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(b.AgentOrigin, "\\%\r\n\t ") {
		return false
	}
	parse := func(raw string) ([]*x509.Certificate, bool) {
		if len(raw) == 0 || len(raw) > 16*1024 {
			return nil, false
		}
		var certs []*x509.Certificate
		rest := []byte(raw)
		for len(bytes.TrimSpace(rest)) > 0 {
			before := rest
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, false
			}
			consumed := before[:len(before)-len(rest)]
			canonical := pem.EncodeToMemory(block)
			if !bytes.Equal(bytes.Join(bytes.Fields(consumed), nil), bytes.Join(bytes.Fields(canonical), nil)) {
				return nil, false
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				return nil, false
			}
			certs = append(certs, cert)
			if len(certs) > 8 {
				return nil, false
			}
		}
		return certs, len(certs) > 0
	}
	issuer, ok := parse(b.IssuerPEM)
	if !ok || len(issuer) != 1 || !bytes.Equal(issuer[0].Raw, service.IssuerDER()) {
		return false
	}
	root, ok := parse(b.IssuerRootPEM)
	if !ok || len(root) != 1 || !bytes.Equal(root[0].Raw, service.RootDER()) || issuer[0].CheckSignatureFrom(root[0]) != nil {
		return false
	}
	if httpTest {
		return b.ServerCAPEM == ""
	}
	_, ok = parse(b.ServerCAPEM)
	return ok
}

// Operator lifecycle errors do not invalidate an otherwise active browser
// session. Only the shared operator authentication boundary emits its 401.
func enrollmentOperatorError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, enrollmentstate.ErrExpired), errors.Is(e, enrollmentstate.ErrState), errors.Is(e, enrollmentstate.ErrConflict):
		fail(w, 409, "enrollment_state_conflict", "Enrollment changed or expired; refresh before continuing.")
	case errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 404, "enrollment_not_found", "Enrollment record is unavailable.")
	case errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentcrypto.ErrProof):
		fail(w, 400, "enrollment_confirmation_mismatch", "The selected key confirmation does not match.")
	default:
		enrollmentError(w, e)
	}
}
