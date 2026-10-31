// nativefixture is a disposable loopback-only protocol peer for native Windows
// agent acceptance. It is NOT a manager, production enrollment endpoint, or
// durable store. Production enrollmentstore intentionally runs only on Linux.
package main

import (
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
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/rustcompat"
)

type challenge struct {
	Context enrollmentcrypto.ChallengeContext `json:"context"`
	Purpose string                            `json:"purpose"`
}
type peer struct {
	mu                             sync.Mutex
	directory, origin, agentOrigin string
	root, issuer                   *x509.Certificate
	signer                         *enrollmentissuer.Issuer
	engine                         *enrollmentstate.Engine
	binding                        enrollmentstate.Binding
	challenges                     map[string]challenge
	certificate                    enrollmentcrypto.VerifiedCertificate
	invitation                     string
	receipt                        lanstore.Receipt
	lastBodyHash                   [32]byte
	reports                        uint64
}

func main() {
	directory := flag.String("directory", "", "fresh disposable fixture directory")
	flag.Parse()
	if err := run(*directory); err != nil {
		fmt.Fprintln(os.Stderr, "Disposable native fixture failed.")
		os.Exit(1)
	}
}

func randomID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("fixture randomness unavailable")
	}
	return prefix + hex.EncodeToString(b[:])
}
func cert(template, parent *x509.Certificate, public ed25519.PublicKey, key ed25519.PrivateKey) (*x509.Certificate, error) {
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}
func asPEM(raw []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}
func writeJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func run(directory string) error {
	if directory == "" {
		return errors.New("missing directory")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	operatorListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer operatorListener.Close()
	agentListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer agentListener.Close()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	rh := sha256.Sum256(rp)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Rust native fixture root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	root, err := cert(rt, rt, rp, rk)
	if err != nil {
		return err
	}
	ip, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ih := sha256.Sum256(ip)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable Rust native fixture client issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	issuer, err := cert(it, root, ip, rk)
	if err != nil {
		return err
	}
	issuerHash := sha256.Sum256(issuer.Raw)
	signer, err := enrollmentissuer.New(issuer.Raw, root.Raw, ik, hex.EncodeToString(issuerHash[:]), now)
	if err != nil {
		return err
	}
	sp, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	st := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Disposable Rust native fixture server"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	serverCert, err := cert(st, root, sp, rk)
	if err != nil {
		return err
	}
	pair := tls.Certificate{Certificate: [][]byte{serverCert.Raw, root.Raw}, PrivateKey: sk}
	p := &peer{directory: directory, origin: "https://" + operatorListener.Addr().String(), agentOrigin: "https://" + agentListener.Addr().String(), root: root, issuer: issuer, signer: signer, challenges: make(map[string]challenge)}
	p.binding = enrollmentstate.Binding{InstanceID: randomID("manager_"), Origin: p.origin, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, IssuerFingerprint: signer.Fingerprint()}
	cfg := enrollmentstate.DefaultConfig(p.binding)
	cfg.RecordLimit = 1
	cfg.InvitationLimit = 1
	cfg.PendingLimit = 1
	p.engine, err = enrollmentstate.New(cfg)
	if err != nil {
		return err
	}
	caFile := filepath.Join(directory, "server-ca.pem")
	if err := os.WriteFile(caFile, []byte(asPEM(root.Raw)), 0600); err != nil {
		return err
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(issuer)
	quiet := log.New(io.Discard, "", 0)
	operator := &http.Server{Handler: http.HandlerFunc(p.enroll), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, ErrorLog: quiet}
	agent := &http.Server{Handler: http.HandlerFunc(p.telemetry), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, ErrorLog: quiet}
	defer operator.Close()
	defer agent.Close()
	errorsOut := make(chan error, 2)
	go func() { errorsOut <- operator.Serve(tls.NewListener(operatorListener, operator.TLSConfig)) }()
	go func() { errorsOut <- agent.Serve(tls.NewListener(agentListener, agent.TLSConfig)) }()
	if err := writeJSON(filepath.Join(directory, "ready.json"), map[string]any{"managerOrigin": p.origin, "agentOrigin": p.agentOrigin, "serverCAFile": caFile, "loopbackOnly": true}); err != nil {
		return err
	}
	timer := time.NewTimer(15 * time.Minute)
	defer timer.Stop()
	select {
	case err := <-errorsOut:
		return err
	case <-timer.C:
		return nil
	}
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func reject(w http.ResponseWriter) {
	reply(w, 400, map[string]string{"error": "fixture_request_rejected"})
}
func (p *peer) enroll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == rustcompat.Path {
		p.capabilities(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method != "POST" || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Host != strings.TrimPrefix(p.origin, "https://") || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
		reject(w)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, enrollmentcrypto.MaxClaimBytes+1))
	if err != nil || len(raw) > enrollmentcrypto.MaxClaimBytes {
		reject(w)
		return
	}
	var input map[string]string
	if json.Unmarshal(raw, &input) != nil {
		reject(w)
		return
	}
	now := time.Now().UTC()
	path := strings.TrimPrefix(r.URL.Path, "/v2/windows/enrollment/")
	if path == "self-bootstrap" {
		if len(input) != 1 || !enrollmentcrypto.ValidID(input["invitationId"], "invite_") {
			reject(w)
			return
		}
		reply(w, 200, map[string]string{"schemaVersion": "tracebolt.enrollment-bootstrap.v2", "managerInstanceId": p.binding.InstanceID, "profile": "tls", "enrollmentOrigin": p.origin, "agentOrigin": p.agentOrigin, "collectionProfile": p.binding.CollectionProfile, "invitationId": input["invitationId"], "serverCaPem": asPEM(p.root.Raw), "issuerRootPem": asPEM(p.root.Raw), "issuerPem": asPEM(p.issuer.Raw)})
		return
	}
	if path == "challenge" {
		purpose := input["purpose"]
		if len(input) != 3 || !enrollmentcrypto.ValidID(input["invitationId"], "invite_") || !enrollmentcrypto.ValidID(input["claimId"], "claim_") || (purpose != "claim" && purpose != "status" && purpose != "credential" && purpose != "activation") {
			reject(w)
			return
		}
		for nonce, c := range p.challenges {
			if c.Context.ExpiresAt <= now.Unix() {
				delete(p.challenges, nonce)
			}
		}
		if len(p.challenges) >= 32 {
			reject(w)
			return
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			reject(w)
			return
		}
		c := challenge{Context: enrollmentcrypto.ChallengeContext{ManagerInstanceID: p.binding.InstanceID, Profile: "tls", Origin: p.origin, CollectionProfile: p.binding.CollectionProfile, InvitationID: input["invitationId"], ClaimID: input["claimId"], Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]), ExpiresAt: now.Unix() + 60}, Purpose: purpose}
		p.challenges[c.Context.Challenge] = c
		reply(w, 200, map[string]any{"schemaVersion": "tracebolt.enrollment-challenge.v2", "context": c.Context, "purpose": purpose, "serverNow": now})
		return
	}
	c, ok := p.challenges[input["challenge"]]
	delete(p.challenges, input["challenge"])
	if !ok || c.Context.ExpiresAt <= now.Unix() {
		reject(w)
		return
	}
	ctx := r.Context()
	if path == "self-claim" && c.Purpose == "claim" {
		proof, err := enrollmentcrypto.VerifyClaim(raw, c.Context, now)
		if err != nil {
			reject(w)
			return
		}
		snapshot, err := p.engine.Get(proof.InvitationID())
		if errors.Is(err, enrollmentstate.ErrNotFound) {
			hash := proof.InvitationHash()
			snapshot, err = p.engine.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: proof.InvitationID(), RequestID: randomID("request_"), InvitationHash: hex.EncodeToString(hash[:]), Platform: "windows", Now: now.Unix()})
		}
		if err != nil {
			reject(w)
			return
		}
		snapshot, err = p.engine.Claim(ctx, enrollmentstate.ClaimCommand{Control: enrollmentstate.Control{InvitationID: proof.InvitationID(), RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, ClaimID: proof.ClaimID()}, proof)
		if err != nil {
			reject(w)
			return
		}
		p.invitation = snapshot.InvitationID
		_ = writeJSON(filepath.Join(p.directory, "pending.json"), map[string]any{"pending": true, "keyFingerprint": snapshot.Claim.KeyFingerprint, "comparisonCode": snapshot.Claim.ComparisonCode})
		reply(w, 200, snapshot)
		return
	}
	snapshot, err := p.engine.Get(c.Context.InvitationID)
	if err != nil {
		reject(w)
		return
	}
	if path == "status" || path == "credential" {
		if c.Purpose != path {
			reject(w)
			return
		}
		key, err := p.engine.TrustedClaimKey(snapshot.InvitationID)
		if err != nil {
			reject(w)
			return
		}
		proof, err := enrollmentcrypto.VerifyStatus(raw, key, c.Context, now)
		if err != nil || proof.Purpose() != path {
			reject(w)
			return
		}
		if snapshot.State == enrollmentstate.ClaimedPending && path == "status" {
			// Test approval is possible only after the local acceptance script has
			// compared and allowlisted the public key printed by the real installer.
			expected, err := os.ReadFile(filepath.Join(p.directory, "expected-fingerprint.txt"))
			if err == nil && strings.TrimSpace(string(expected)) == snapshot.Claim.KeyFingerprint {
				snapshot, err = p.engine.Approve(ctx, enrollmentstate.ApproveCommand{Control: enrollmentstate.Control{InvitationID: snapshot.InvitationID, RequestID: randomID("request_"), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, DeviceID: randomID("agent_"), KeyFingerprint: snapshot.Claim.KeyFingerprint})
				if err != nil {
					reject(w)
					return
				}
				snapshot, err = p.issue(ctx, snapshot, now)
				if err != nil {
					reject(w)
					return
				}
			}
		}
		if path == "status" {
			reply(w, 200, snapshot)
			return
		}
		if (snapshot.State != enrollmentstate.Issued && snapshot.State != enrollmentstate.Activated) || !p.certificate.Valid() {
			reject(w)
			return
		}
		reply(w, 200, map[string]any{"schemaVersion": "tracebolt.enrollment-credential.v2", "certificateDer": base64.RawStdEncoding.EncodeToString(p.certificate.DER()), "issuerDer": base64.RawStdEncoding.EncodeToString(p.issuer.Raw), "intent": p.certificate.Intent()})
		return
	}
	if path == "activate" && c.Purpose == "activation" {
		proof, err := enrollmentcrypto.VerifyActivation(raw, p.certificate, c.Context, now)
		if err != nil {
			reject(w)
			return
		}
		snapshot, err = p.engine.Activate(ctx, enrollmentstate.Control{InvitationID: snapshot.InvitationID, RequestID: proof.RequestID(), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, proof)
		if err != nil {
			reject(w)
			return
		}
		reply(w, 200, snapshot)
		return
	}
	reject(w)
}

func (p *peer) issue(ctx context.Context, snapshot enrollmentstate.Snapshot, now time.Time) (enrollmentstate.Snapshot, error) {
	snapshot, err := p.engine.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: enrollmentstate.Control{InvitationID: snapshot.InvitationID, RequestID: randomID("request_"), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, IntentID: randomID("intent_"), SerialHex: randomID(""), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Add(-30 * time.Second).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	if err != nil {
		return snapshot, err
	}
	intent, err := p.engine.SigningIntent(snapshot.InvitationID, now.Unix())
	if err != nil {
		return snapshot, err
	}
	p.certificate, err = p.signer.Sign(ctx, intent, now)
	if err != nil {
		return snapshot, err
	}
	return p.engine.CommitIssued(ctx, enrollmentstate.Control{InvitationID: snapshot.InvitationID, RequestID: randomID("request_"), ExpectedRevision: snapshot.Revision, Now: now.Unix()}, p.certificate)
}

func (p *peer) telemetry(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method != "POST" || r.URL.Path != "/v1/windows/agent/telemetry" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || !p.certificate.Valid() || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, p.certificate.DER()) {
		reject(w)
		return
	}
	snapshot, err := p.engine.Get(p.invitation)
	if err != nil || snapshot.State != enrollmentstate.Activated {
		reject(w)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, lanstore.MaxFrameBytes+1))
	if err != nil || len(raw) > lanstore.MaxFrameBytes {
		reject(w)
		return
	}
	now := time.Now().UTC()
	frame, err := lanstore.ValidateFrame(raw, now)
	if err != nil || !lanstore.FrameMatchesCollectionProfile(frame, snapshot.Binding.CollectionProfile) {
		reject(w)
		return
	}
	hash := sha256.Sum256(raw)
	if frame.Sequence == p.receipt.Sequence && hash == p.lastBodyHash {
		duplicate := p.receipt
		duplicate.Duplicate = true
		reply(w, 200, duplicate)
		return
	}
	if frame.Sequence <= p.receipt.Sequence {
		reject(w)
		return
	}
	p.receipt = lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: snapshot.Approval.DeviceID, Sequence: frame.Sequence, CollectedAt: frame.Observation.Observation.LastSeen, ReceivedAt: now}
	p.lastBodyHash = hash
	p.reports++
	device := frame.Observation.Observation
	// Public acceptance metadata only. No observation values or raw payloads are
	// retained, logged or uploaded from the native test runner.
	if err := writeJSON(filepath.Join(p.directory, "accepted.json"), map[string]any{"accepted": true, "count": p.reports, "sequence": frame.Sequence, "mutualTLS": true, "activated": true, "cpuAvailable": device.CPU.Value != nil, "memoryAvailable": device.Memory.Value != nil, "diskAvailable": device.Disk.Value != nil}); err != nil {
		reject(w)
		return
	}
	reply(w, 200, p.receipt)
}

// The disposable peer exposes only the same static basic contract; GET never
// enters enrollment parsing or touches invitations, challenges, or files.
func (p *peer) capabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || !r.TLS.HandshakeComplete || r.Host != strings.TrimPrefix(p.origin, "https://") || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.EscapedPath() != r.URL.Path || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 {
		reject(w)
		return
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		switch lower {
		case "cookie", "origin", "authorization", "proxy-authorization", "forwarded", "x-csrf-token", "content-type", "content-encoding", "range", "if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range", "x-real-ip":
			reject(w)
			return
		}
		if strings.HasPrefix(lower, "x-forwarded-") {
			reject(w)
			return
		}
	}
	raw, err := json.Marshal(rustcompat.Expected(p.origin, p.agentOrigin, true))
	if err != nil || len(raw) > 2048 {
		reject(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
