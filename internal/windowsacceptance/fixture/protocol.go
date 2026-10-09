package fixture

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsacceptance/profile"
)

const prefix = "/v2/enrollment/"
const telemetryPath = "/v1/agent/telemetry"

func (f *Fixture) serve(w http.ResponseWriter, r *http.Request, agent bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if f == nil || f.state == nil {
		fail(w, 503)
		return
	}
	s := f.state
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 429)
		return
	}
	origin := s.bootstrap.EnrollmentOrigin
	if agent {
		origin = s.bootstrap.AgentOrigin
	}
	limit := enrollmentcrypto.MaxClaimBytes
	if agent {
		limit = lanstore.MaxFrameBytes
	}
	setupCapabilities := !agent && s.expanded && setupCapabilitiesRequest(r, origin, s.selection)
	if !setupCapabilities && !validRequestSelected(r, origin, agent, s.selection) {
		fail(w, 400)
		return
	}
	if r.ContentLength > int64(limit) {
		fail(w, 413)
		return
	}
	// Check the outage before consuming or retaining body material. Status and
	// receipts remain unchanged; pending-service timeout still uses the real clock.
	s.mu.Lock()
	blocked := s.closed || s.ctx.Err() != nil || s.requests >= MaxRequests
	if !blocked {
		s.requests++
		if s.unavailable {
			s.unavailableRequests++
			blocked = true
		}
	}
	s.mu.Unlock()
	if blocked {
		fail(w, 503)
		return
	}
	if setupCapabilities {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.writeSetupCapabilities(w)
		return
	}
	var raw []byte
	var verified *signedhttp.Verified
	var err error
	if agent && s.selection.HTTPTest() {
		v, e := s.signed.Verify(r)
		if e != nil {
			fail(w, 403)
			return
		}
		verified, raw = &v, v.Body
	} else {
		raw, err = io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	}
	defer clear(raw)
	if err != nil || len(raw) > limit || int64(len(raw)) != r.ContentLength {
		fail(w, 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.unavailable || s.ctx.Err() != nil || r.Context().Err() != nil {
		fail(w, 503)
		return
	}
	if agent {
		s.telemetry(w, r, raw, verified)
		return
	}
	if r.URL.Path == s.selection.EnrollmentPrefix()+"challenge" {
		s.challenge(w, raw)
		return
	}
	s.proof(w, r, raw)
}

func validRequest(r *http.Request, origin string, agent bool) bool {
	return validRequestSelected(r, origin, agent, profile.BasicTLS())
}

func validRequestSelected(r *http.Request, origin string, agent bool, selection profile.Selection) bool {
	u, e := url.Parse(origin)
	if e != nil || selection.Validate() != nil || !validOrigin(origin, selection) || r == nil || r.URL == nil || r.Method != http.MethodPost || r.Host != u.Host || r.Body == nil || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return false
	}
	if selection.HTTPTest() {
		if r.TLS != nil {
			return false
		}
	} else if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		return false
	}
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Scheme != "" && r.URL.Scheme != u.Scheme || r.URL.Host != "" && r.URL.Host != u.Host || r.RequestURI != "" && r.RequestURI != r.URL.Path {
		return false
	}
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	if agent {
		if r.URL.Path != selection.TelemetryPath() {
			return false
		}
	} else {
		p := selection.EnrollmentPrefix()
		switch r.URL.Path {
		case p + "challenge", p + "claim", p + "status", p + "credential", p + "activate":
		default:
			return false
		}
	}
	size, types, lengths := 128, 0, 0
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "origin" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-fetch-") || lower == "content-encoding" || lower == "trailer" || lower == "transfer-encoding" || lower == "expect" || lower == "upgrade" || lower == "host" {
			return false
		}
		if strings.HasPrefix(lower, "x-tracebolt-") {
			if !agent || !selection.HTTPTest() {
				return false
			}
			switch lower {
			case strings.ToLower(signedhttp.CertificateHeader), strings.ToLower(signedhttp.SequenceHeader), strings.ToLower(signedhttp.SignedAtHeader), strings.ToLower(signedhttp.SignatureHeader):
			default:
				return false
			}
		}
		if lower == "content-type" {
			types += len(values)
			if len(values) != 1 || values[0] != "application/json" {
				return false
			}
		}
		if lower == "content-length" {
			lengths += len(values)
			if len(values) != 1 || values[0] != strconv.FormatInt(r.ContentLength, 10) {
				return false
			}
		}
		for _, v := range values {
			size += len(key) + len(v) + 4
			if size > 8192 {
				return false
			}
		}
	}
	return types == 1 && lengths <= 1
}

// stringsObject admits only one flat string-valued JSON object; duplicates,
// mixed case, unknown fields, missing fields, null and trailing data fail closed.
// Proofs are additionally parsed by the real enrollmentcrypto strict decoders.
func stringsObject(raw []byte, fields ...string) (map[string]string, bool) {
	if len(raw) == 0 || len(raw) > enrollmentcrypto.MaxClaimBytes || !utf8.Valid(raw) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, false
	}
	allowed := make(map[string]bool, len(fields))
	for _, k := range fields {
		allowed[k] = true
	}
	out := make(map[string]string, len(fields))
	for d.More() {
		k, e := d.Token()
		key, ok := k.(string)
		if e != nil || !ok || !allowed[key] {
			return nil, false
		}
		if _, exists := out[key]; exists {
			return nil, false
		}
		v, e := d.Token()
		value, ok := v.(string)
		if e != nil || !ok || strings.ContainsRune(value, utf8.RuneError) {
			return nil, false
		}
		out[key] = value
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') || len(out) != len(fields) {
		return nil, false
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, false
	}
	return out, true
}

func (s *state) challenge(w http.ResponseWriter, raw []byte) {
	in, ok := stringsObject(raw, "invitationId", "claimId", "purpose")
	if !ok || in["invitationId"] != s.bootstrap.InvitationID || !enrollmentcrypto.ValidID(in["claimId"], "claim_") {
		fail(w, 400)
		return
	}
	purpose := in["purpose"]
	switch purpose {
	case "claim", "status", "credential", "activation":
	default:
		fail(w, 400)
		return
	}
	now := s.now().UTC()
	v, e := s.snapshot()
	if e != nil || now.Unix() < v.UpdatedAt || now.Unix() >= deadline(v) {
		fail(w, 401)
		return
	}
	// Pre-claim status receives a challenge and then a proof rejection. This is
	// the native client's existing claim/reconciliation protocol, not auto-claim.
	if v.Claim.ClaimID != "" && v.Claim.ClaimID != in["claimId"] {
		fail(w, 401)
		return
	}
	for nonce, c := range s.challenges {
		if c.context.ExpiresAt <= now.Unix() {
			delete(s.challenges, nonce)
		}
	}
	if len(s.challenges) >= MaxChallenges {
		fail(w, 429)
		return
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		fail(w, 503)
		return
	}
	c := enrollmentcrypto.ChallengeContext{ManagerInstanceID: s.bootstrap.ManagerInstanceID, Profile: s.selection.Transport, Origin: s.bootstrap.EnrollmentOrigin, CollectionProfile: s.selection.CollectionProfile, InvitationID: s.bootstrap.InvitationID, ClaimID: in["claimId"], Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]), ExpiresAt: now.Add(60 * time.Second).Unix()}
	s.challenges[c.Challenge] = challenge{context: c, purpose: purpose}
	write(w, struct {
		SchemaVersion string                            `json:"schemaVersion"`
		Context       enrollmentcrypto.ChallengeContext `json:"context"`
		Purpose       string                            `json:"purpose"`
		ServerNow     time.Time                         `json:"serverNow"`
	}{"tracebolt.enrollment-challenge.v2", c, purpose, now})
}

func (s *state) proof(w http.ResponseWriter, r *http.Request, raw []byte) {
	purpose := strings.TrimPrefix(r.URL.Path, s.selection.EnrollmentPrefix())
	if purpose == "activate" {
		purpose = "activation"
	}
	fields := []string{"schemaVersion", "managerInstanceId", "profile", "origin", "collectionProfile", "invitationId", "claimId", "requestId", "challenge"}
	switch purpose {
	case "claim":
		fields = append(fields, "invitationSecret", "csr", "proof")
	case "status", "credential":
		fields = append(fields, "keyFingerprint", "purpose", "proof")
	case "activation":
		fields = []string{"schemaVersion", "managerInstanceId", "profile", "origin", "deviceId", "intentId", "certificateHash", "requestId", "challenge", "proof"}
	default:
		fail(w, 400)
		return
	}
	in, ok := stringsObject(raw, fields...)
	if !ok {
		fail(w, 400)
		return
	}
	c, ok := s.challenges[in["challenge"]]
	delete(s.challenges, in["challenge"])
	now := s.now().UTC()
	v, e := s.snapshot()
	if !ok || c.purpose != purpose || c.context.ExpiresAt <= now.Unix() || e != nil || now.Unix() < v.UpdatedAt || now.Unix() >= deadline(v) {
		fail(w, 401)
		return
	}
	switch purpose {
	case "claim":
		proof, err := enrollmentcrypto.VerifyClaim(raw, c.context, now)
		delete(in, "invitationSecret")
		if err != nil {
			fail(w, 401)
			return
		}
		v, err = s.engine.Claim(r.Context(), enrollmentstate.ClaimCommand{Control: control(v, proof.RequestID(), now), ClaimID: proof.ClaimID()}, proof)
		if err != nil {
			fail(w, 401)
			return
		}
		s.publicKey = proof.PublicKeyDER()
		write(w, v)
	case "status", "credential":
		proof, err := enrollmentcrypto.VerifyStatus(raw, s.publicKey, c.context, now)
		if err != nil || proof.Purpose() != purpose || proof.ClaimID() != v.Claim.ClaimID || proof.KeyFingerprint() != v.Claim.KeyFingerprint {
			fail(w, 401)
			return
		}
		if purpose == "status" {
			write(w, v)
			return
		}
		if v.State != enrollmentstate.Issued && v.State != enrollmentstate.Activated || !s.issued.Valid() {
			fail(w, 409)
			return
		}
		write(w, struct {
			SchemaVersion  string                  `json:"schemaVersion"`
			CertificateDER string                  `json:"certificateDer"`
			IssuerDER      string                  `json:"issuerDer"`
			Intent         enrollmentcrypto.Intent `json:"intent"`
		}{"tracebolt.enrollment-credential.v2", base64.RawStdEncoding.EncodeToString(s.issued.DER()), base64.RawStdEncoding.EncodeToString(s.issuerCert.Raw), s.issued.Intent()})
	case "activation":
		proof, err := enrollmentcrypto.VerifyActivation(raw, s.issued, c.context, now)
		if err != nil {
			fail(w, 401)
			return
		}
		v, err = s.engine.Activate(r.Context(), control(v, proof.RequestID(), now), proof)
		if err != nil {
			fail(w, 401)
			return
		}
		write(w, v)
	}
}

func deadline(v enrollmentstate.Snapshot) int64 {
	if v.State == enrollmentstate.Activated {
		return v.Intent.NotAfter
	}
	return v.DeadlineAt
}

func (s *state) telemetry(w http.ResponseWriter, r *http.Request, raw []byte, signed *signedhttp.Verified) {
	now := s.now().UTC()
	v, e := s.snapshot()
	if e != nil || !s.activeIdentity(v, now) {
		fail(w, 403)
		return
	}
	if s.selection.HTTPTest() {
		// Final authority check shares the replay/receipt lock; verification alone
		// cannot keep an expired, closed, or otherwise changed identity active.
		current, err := s.authorizeCertificate(s.issued.DER(), now)
		if err != nil || signed == nil || signed.Agent != current || !bytes.Equal(signed.Body, raw) || r.TLS != nil {
			fail(w, 403)
			return
		}
	} else if signed != nil || !s.verifyPeer(r, v, now) {
		fail(w, 403)
		return
	}
	hash := sha256.Sum256(raw)
	// Exact latest bytes were already validated. Check retry before sample-age
	// and capture fences so an outage never refreshes or invalidates its receipt.
	if s.frames > 0 && hash == s.lastDigest && (signed == nil || signed.Sequence == s.lastReceipt.Sequence && signed.SignedAt.Equal(s.lastGenerated)) {
		receipt := s.lastReceipt
		receipt.Duplicate = true
		s.duplicates++
		write(w, receipt)
		return
	}
	frame, e := lanstore.ValidateFrame(raw, now)
	if e != nil || frame.Observation.Platform != "windows" || !lanstore.FrameMatchesCollectionProfile(frame, s.selection.CollectionProfile) {
		fail(w, 400)
		return
	}
	if signed != nil && (signed.Sequence != frame.Sequence || !signed.SignedAt.Equal(frame.Observation.GeneratedAt)) {
		fail(w, 400)
		return
	}
	if !s.extensionShape(frame) {
		fail(w, 400)
		return
	}
	if !s.extensionAdvance(frame) {
		fail(w, 409)
		return
	}
	if frame.Sequence <= s.lastReceipt.Sequence || !s.lastReceipt.CollectedAt.IsZero() && !frame.Observation.Observation.LastSeen.After(s.lastReceipt.CollectedAt) || !s.lastGenerated.IsZero() && !frame.Observation.GeneratedAt.After(s.lastGenerated) {
		fail(w, 409)
		return
	}
	if frame.WindowsInventory != nil && s.frames > 0 && (frame.WindowsInventory.GenerationID == s.lastWindowsGeneration || !frame.WindowsInventory.CollectedAt.After(s.lastWindowsCollected)) {
		fail(w, 409)
		return
	}
	if s.frames >= MaxFrames {
		fail(w, 503)
		return
	}
	s.lastReceipt = lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: v.Approval.DeviceID, Sequence: frame.Sequence, CollectedAt: frame.Observation.Observation.LastSeen, ReceivedAt: now}
	s.lastDigest = hash
	s.lastGenerated = frame.Observation.GeneratedAt
	s.frames++
	if inventory := frame.WindowsInventory; inventory != nil {
		s.lastWindowsGeneration, s.lastWindowsCollected = inventory.GenerationID, inventory.CollectedAt
		d := frame.Observation.Observation
		s.inventory = profile.Observation{Frames: s.frames, CPU: metricQuality(d.CPU.Quality), Memory: metricQuality(d.Memory.Quality), Disk: metricQuality(d.Disk.Quality), Hostname: inventory.Hostname.Quality, Processes: inventory.Processes.Quality, Services: inventory.Services.Quality, Software: inventory.Software.Quality, Interfaces: inventory.Network.Quality}
	}
	s.observeExtensions(frame)
	write(w, s.lastReceipt)
	// No raw body, bundle, metric, label, or observation is retained in state.
}

func metricQuality(q string) string {
	switch q {
	case "healthy", "partial", "denied":
		return q
	default:
		return "unavailable"
	}
}

func (s *state) verifyPeer(r *http.Request, v enrollmentstate.Snapshot, now time.Time) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil || s.issuerCert == nil {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	if digest(leaf.Raw) != v.Issuance.CertificateHash || !bytes.Equal(leaf.Raw, s.issued.DER()) {
		return false
	}
	matched := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) == 2 && chain[0] != nil && chain[1] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) && bytes.Equal(chain[1].Raw, s.issuerCert.Raw) {
			matched = true
		}
	}
	if !matched {
		return false
	}
	chains, e := leaf.Verify(x509.VerifyOptions{Roots: s.clientRoots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if e != nil {
		return false
	}
	for _, chain := range chains {
		if len(chain) == 2 && bytes.Equal(chain[1].Raw, s.issuerCert.Raw) {
			return true
		}
	}
	return false
}

func write(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int) {
	code, message := "fixture_request_rejected", "Disposable acceptance request was rejected."
	if status == 401 {
		code = "enrollment_proof_rejected"
		message = "Enrollment proof is invalid or expired."
	}
	if status == 400 {
		code = "invalid_enrollment_request"
		message = "Enrollment request is invalid or unsupported."
	}
	w.Header().Set("Content-Type", "application/json")
	if status == 429 {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
