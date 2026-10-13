package main

// This is a SCRIPTED LOOPBACK PEER, not a manager implementation. It deliberately
// uses the portable cryptographic/wire contracts and process-local lifecycle
// model, never enrollmentstore.Open or lanstore.Open. No SQLite durability,
// operator authentication, Linux-manager restart or release acceptance follows.
// All functions here are unreachable from main pending a reviewed runtime gate.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanconfig"
)

const controlLimit = 4096

var errFixture = errors.New("fixture_contract_failed")

type command struct {
	Command     string `json:"command"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Comparison  string `json:"comparison,omitempty"`
}

func decodeCommand(raw []byte) (command, error) {
	var c command
	if len(raw) == 0 || len(raw) > controlLimit {
		return c, errFixture
	}
	var tag struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(raw, &tag) != nil {
		return c, errFixture
	}
	keys := []string{"command"}
	if tag.Command == "approve" {
		keys = append(keys, "fingerprint", "comparison")
	}
	if lanconfig.StrictObject(raw, &c, keys...) != nil {
		return c, errFixture
	}
	switch c.Command {
	case "start", "arm_loss", "status", "stop":
	case "approve":
		if !enrollmentcrypto.ValidHash(c.Fingerprint) || len(c.Comparison) != 32 {
			return c, errFixture
		}
		if b, e := hex.DecodeString(c.Comparison); e != nil || hex.EncodeToString(b) != c.Comparison {
			return c, errFixture
		}
	default:
		return c, errFixture
	}
	return c, nil
}

type peerStatus struct {
	Activated             bool `json:"activated"`
	TLS13                 bool `json:"tls13"`
	CurrentLeaf           bool `json:"currentLeaf"`
	MissingClientRejected bool `json:"missingClientRejected"`
	BasicOnly             bool `json:"basicOnly"`
	SourceSemantics       bool `json:"sourceSemantics"`
	ExactRetry            bool `json:"exactRetry"`
	OriginalReceiptTime   bool `json:"originalReceiptTime"`
	NextSequence          bool `json:"nextSequence"`
	AcceptedReports       int  `json:"acceptedReports"`
	DuplicateReports      int  `json:"duplicateReports"`
	LossCount             int  `json:"lossCount"`
}
type approval struct {
	FingerprintMatched bool `json:"fingerprintMatched"`
	ComparisonMatched  bool `json:"comparisonMatched"`
	Approved           bool `json:"approved"`
}
type challenge struct {
	context enrollmentcrypto.ChallengeContext
	purpose string
}
type scriptedPeer struct {
	mu         sync.Mutex
	bootstrap  enrollmentclient.Bootstrap
	invitation string
	engine     *enrollmentstate.Engine
	issuer     *enrollmentissuer.Issuer
	issued     enrollmentcrypto.VerifiedCertificate
	publicKey  []byte
	challenges map[string]challenge
	servers    []*http.Server
	listeners  []net.Listener
	joined     sync.WaitGroup
	status     peerStatus
	receipts   receiptMemory
	armLoss    bool
	failed     bool
}

// runPeer is the only future pipe-protocol entry. It is deliberately not called
// by main, tests, package initialization, flags or environment variables.
func runPeer(ctx context.Context, input io.Reader, output io.Writer) error {
	if runtime.GOOS != "darwin" {
		return errFixture
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	lines := make(chan []byte)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(input)
		s.Buffer(make([]byte, controlLimit), controlLimit)
		for s.Scan() {
			raw := bytes.Clone(s.Bytes())
			select {
			case lines <- raw:
			case <-ctx.Done():
				return
			}
		}
	}()
	var p *scriptedPeer
	defer func() {
		if p != nil {
			p.close()
		}
	}()
	out := json.NewEncoder(output)
	for n := 0; n < 128; n++ {
		var raw []byte
		select {
		case <-ctx.Done():
			return errFixture
		case v, ok := <-lines:
			if !ok {
				return errFixture
			}
			raw = v
		}
		c, e := decodeCommand(raw)
		if e != nil {
			return errFixture
		}
		var result any
		switch c.Command {
		case "start":
			if p != nil {
				return errFixture
			}
			p, e = newScriptedPeer(ctx)
			if e != nil {
				return errFixture
			}
			result = struct {
				Bootstrap  enrollmentclient.Bootstrap `json:"bootstrap"`
				Invitation string                     `json:"invitation"`
			}{p.bootstrap, p.invitation}
		case "approve":
			if p == nil {
				return errFixture
			}
			result, e = p.approve(c.Fingerprint, c.Comparison)
		case "arm_loss":
			if p == nil {
				return errFixture
			}
			p.mu.Lock()
			armed := !p.failed && p.status.AcceptedReports == 1 && p.status.LossCount == 0 && !p.armLoss
			p.armLoss = armed
			p.mu.Unlock()
			result = struct {
				Armed bool `json:"armed"`
			}{armed}
		case "status":
			if p == nil {
				return errFixture
			}
			p.mu.Lock()
			s := p.status
			if p.failed {
				s.BasicOnly = false
				s.SourceSemantics = false
			}
			p.mu.Unlock()
			result = s
		case "stop":
			if p == nil {
				return errFixture
			}
			stopped := p.close()
			p = nil
			return out.Encode(struct {
				Stopped bool `json:"stopped"`
			}{stopped})
		}
		if e != nil {
			return errFixture
		}
		if out.Encode(result) != nil {
			return errFixture
		}
	}
	return errFixture
}

func fingerprint(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func certPEM(raw []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}
func fixtureID(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

// Real disposable test keys are created ONLY here, in a future approved run.
// Root/server/issuer private keys are never written or returned on the pipe.
func newScriptedPeer(ctx context.Context) (_ *scriptedPeer, err error) {
	p := &scriptedPeer{challenges: make(map[string]challenge)}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	now := time.Now().UTC()
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, errFixture
	}
	defer clear(rk)
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, errFixture
	}
	defer clear(ik)
	sp, sk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, errFixture
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable endpoint fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("endpoint-fixture-root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		return nil, errFixture
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		return nil, errFixture
	}
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable endpoint fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("endpoint-fixture-issuer")}
	id, e := x509.CreateCertificate(rand.Reader, it, root, ip, rk)
	if e != nil {
		return nil, errFixture
	}
	issuerCert, e := x509.ParseCertificate(id)
	if e != nil {
		return nil, errFixture
	}
	p.issuer, e = enrollmentissuer.New(id, rd, ik, fingerprint(id), now)
	if e != nil {
		return nil, errFixture
	}
	st := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Disposable literal loopback peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	sd, e := x509.CreateCertificate(rand.Reader, st, root, sp, rk)
	if e != nil {
		return nil, errFixture
	}
	for range 2 {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			return nil, errFixture
		}
		p.listeners = append(p.listeners, l)
	}
	enrollOrigin := "https://" + p.listeners[0].Addr().String()
	agentOrigin := "https://" + p.listeners[1].Addr().String()
	if enrollOrigin == agentOrigin {
		return nil, errFixture
	}
	binding := enrollmentstate.Binding{InstanceID: fixtureID("manager", 1), Profile: "tls", Origin: enrollOrigin, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: fingerprint(id)}
	cfg := enrollmentstate.DefaultConfig(binding)
	cfg.Platform = "darwin"
	cfg.RecordLimit = 1
	cfg.InvitationLimit = 1
	cfg.PendingLimit = 1
	p.engine, e = enrollmentstate.New(cfg)
	if e != nil {
		return nil, errFixture
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return nil, errFixture
	}
	p.invitation = base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	ih, e := enrollmentcrypto.InvitationHash(p.invitation)
	if e != nil {
		return nil, errFixture
	}
	_, e = p.engine.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: fixtureID("invite", 1), RequestID: fixtureID("request", 1), InvitationHash: hex.EncodeToString(ih[:]), Platform: "darwin", Now: now.Unix()})
	if e != nil {
		return nil, errFixture
	}
	p.bootstrap = enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: binding.InstanceID, Profile: "tls", EnrollmentOrigin: enrollOrigin, AgentOrigin: agentOrigin, CollectionProfile: binding.CollectionProfile, InvitationID: fixtureID("invite", 1), ServerCAPEM: certPEM(rd), IssuerRootPEM: certPEM(rd), IssuerPEM: certPEM(id)}
	clientCA := x509.NewCertPool()
	clientCA.AddCert(issuerCert)
	for i, l := range p.listeners {
		tc := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{sd}, PrivateKey: sk}}, NextProtos: []string{"http/1.1"}}
		h := http.HandlerFunc(p.enrollment)
		if i == 1 {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
			tc.ClientCAs = clientCA
			h = p.report
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
		p.servers = append(p.servers, srv)
		p.joined.Add(1)
		go func(s *http.Server, ln net.Listener, c *tls.Config) {
			defer p.joined.Done()
			_ = s.Serve(tls.NewListener(ln, c))
		}(srv, l, tc)
	}
	// The intentionally certificate-less probe validates the explicit server root
	// and literal IP SAN. A TLS alert on HTTP read is required, not merely any error.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	probe := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, ForceAttemptHTTP2: false}
	client := &http.Client{Transport: probe, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errFixture }}
	req, e := http.NewRequestWithContext(ctx, "POST", agentOrigin+"/v1/macos/telemetry", bytes.NewReader([]byte("{}")))
	if e != nil {
		return nil, errFixture
	}
	res, e := client.Do(req)
	if res != nil {
		res.Body.Close()
	}
	probe.CloseIdleConnections()
	// This exact Go TLS remote alert denotes absence of a required client leaf.
	// Timeouts, connect errors, untrusted server roots and wrong SANs are not passes.
	p.status.MissingClientRejected = e != nil && strings.Contains(e.Error(), "remote error: tls: certificate required")
	if !p.status.MissingClientRejected {
		return nil, errFixture
	}
	return p, nil
}

func (p *scriptedPeer) close() bool {
	// Shutdown joins ordinary active HTTP handlers; hijacked loss connections are
	// closed synchronously in report. Close is a bounded fallback, never a pass.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	joined := true
	for _, s := range p.servers {
		if s.Shutdown(ctx) != nil {
			joined = false
		}
		_ = s.Close()
	}
	for _, l := range p.listeners {
		_ = l.Close()
	}
	p.joined.Wait()
	p.mu.Lock()
	p.invitation = ""
	p.issuer = nil
	clear(p.publicKey)
	clear(p.receipts.body)
	p.receipts = receiptMemory{}
	p.mu.Unlock()
	return joined
}

func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
func reject(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":{"code":"fixture_rejected","message":"Fixture request rejected."}}`)
}
func (p *scriptedPeer) control(requestID string, s enrollmentstate.Snapshot) enrollmentstate.Control {
	return enrollmentstate.Control{InvitationID: s.InvitationID, RequestID: requestID, ExpectedRevision: s.Revision, Now: time.Now().Unix()}
}

func (p *scriptedPeer) enrollment(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Fragment != "" || r.Host != strings.TrimPrefix(p.bootstrap.EnrollmentOrigin, "https://") || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		reject(w, 400)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, enrollmentcrypto.MaxClaimBytes+1))
	if e != nil || len(raw) > enrollmentcrypto.MaxClaimBytes {
		reject(w, 400)
		return
	}
	defer clear(raw)
	path := strings.TrimPrefix(r.URL.Path, enrollmentclient.MacOSEnrollmentPathPrefix)
	s, e := p.engine.Get(p.bootstrap.InvitationID)
	if e != nil {
		reject(w, 503)
		return
	}
	if path == "challenge" {
		var in struct {
			InvitationID string `json:"invitationId"`
			ClaimID      string `json:"claimId"`
			Purpose      string `json:"purpose"`
		}
		if lanconfig.StrictObject(raw, &in, "invitationId", "claimId", "purpose") != nil || in.InvitationID != s.InvitationID || !enrollmentcrypto.ValidID(in.ClaimID, "claim_") || len(p.challenges) >= 64 {
			reject(w, 400)
			return
		}
		switch in.Purpose {
		case "claim", "status", "credential", "activation":
		default:
			reject(w, 400)
			return
		}
		if s.Claim.ClaimID != "" && in.ClaimID != s.Claim.ClaimID {
			reject(w, 401)
			return
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			reject(w, 503)
			return
		}
		c := enrollmentcrypto.ChallengeContext{ManagerInstanceID: p.bootstrap.ManagerInstanceID, Profile: "tls", Origin: p.bootstrap.EnrollmentOrigin, CollectionProfile: enrollmentcrypto.CollectionProfile, InvitationID: in.InvitationID, ClaimID: in.ClaimID, Challenge: base64.RawURLEncoding.EncodeToString(nonce), ExpiresAt: time.Now().Add(60 * time.Second).Unix()}
		clear(nonce)
		p.challenges[c.Challenge] = challenge{c, in.Purpose}
		jsonReply(w, struct {
			SchemaVersion string                            `json:"schemaVersion"`
			Context       enrollmentcrypto.ChallengeContext `json:"context"`
			Purpose       string                            `json:"purpose"`
			ServerNow     string                            `json:"serverNow"`
		}{"tracebolt.enrollment-challenge.v2", c, in.Purpose, time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	var lookup struct {
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal(raw, &lookup) != nil {
		reject(w, 400)
		return
	}
	c, ok := p.challenges[lookup.Challenge]
	delete(p.challenges, lookup.Challenge)
	purpose := path
	if path == "activate" {
		purpose = "activation"
	}
	if !ok || c.purpose != purpose {
		reject(w, 401)
		return
	}
	now := time.Now().UTC()
	switch path {
	case "claim":
		proof, e := enrollmentcrypto.VerifyClaim(raw, c.context, now)
		if e != nil {
			reject(w, 401)
			return
		}
		s, e = p.engine.Claim(r.Context(), enrollmentstate.ClaimCommand{Control: p.control(proof.RequestID(), s), ClaimID: proof.ClaimID()}, proof)
		if e != nil {
			reject(w, 409)
			return
		}
		p.publicKey = proof.PublicKeyDER()
		jsonReply(w, s)
	case "status", "credential":
		if len(p.publicKey) == 0 {
			reject(w, 401)
			return
		}
		proof, e := enrollmentcrypto.VerifyStatus(raw, p.publicKey, c.context, now)
		if e != nil || proof.Purpose() != path {
			reject(w, 401)
			return
		}
		if path == "status" {
			jsonReply(w, s)
			return
		}
		if !p.issued.Valid() || (s.State != enrollmentstate.Issued && s.State != enrollmentstate.Activated) {
			reject(w, 409)
			return
		}
		jsonReply(w, struct {
			SchemaVersion  string                  `json:"schemaVersion"`
			CertificateDER string                  `json:"certificateDer"`
			IssuerDER      string                  `json:"issuerDer"`
			Intent         enrollmentcrypto.Intent `json:"intent"`
		}{"tracebolt.enrollment-credential.v2", base64.RawStdEncoding.EncodeToString(p.issued.DER()), base64.RawStdEncoding.EncodeToString(p.issuer.IssuerDER()), p.issued.Intent()})
	case "activate":
		proof, e := enrollmentcrypto.VerifyActivation(raw, p.issued, c.context, now)
		if e != nil {
			reject(w, 401)
			return
		}
		s, e = p.engine.Activate(r.Context(), p.control(proof.RequestID(), s), proof)
		if e != nil {
			reject(w, 409)
			return
		}
		p.status.Activated = s.State == enrollmentstate.Activated
		jsonReply(w, s)
	default:
		reject(w, 404)
	}
}

func (p *scriptedPeer) approve(fp, comparison string) (approval, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := approval{}
	s, e := p.engine.Get(p.bootstrap.InvitationID)
	if e != nil {
		return a, errFixture
	}
	if s.State != enrollmentstate.ClaimedPending {
		return a, nil
	}
	a.FingerprintMatched = fp == s.Claim.KeyFingerprint
	a.ComparisonMatched = comparison == s.Claim.ComparisonCode
	if !a.FingerprintMatched || !a.ComparisonMatched {
		return a, nil
	}
	ctx := context.Background()
	s, e = p.engine.Approve(ctx, enrollmentstate.ApproveCommand{Control: p.control(fixtureID("request", 2), s), DeviceID: fixtureID("agent", 1), KeyFingerprint: fp})
	if e != nil {
		return a, errFixture
	}
	now := time.Now().UTC()
	s, e = p.engine.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: p.control(fixtureID("request", 3), s), IntentID: fixtureID("intent", 1), SerialHex: strings.Repeat("0", 31) + "4", TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	if e != nil {
		return a, errFixture
	}
	intent, e := p.engine.SigningIntent(s.InvitationID, time.Now().Unix())
	if e != nil {
		return a, errFixture
	}
	p.issued, e = p.issuer.Sign(ctx, intent, time.Now().UTC())
	if e != nil {
		return a, errFixture
	}
	_, e = p.engine.CommitIssued(ctx, p.control(fixtureID("request", 4), s), p.issued)
	if e != nil {
		return a, errFixture
	}
	a.Approved = true
	return a, nil
}
