// Package fixture is a disposable, process-local protocol peer for the explicitly
// authorized Windows native acceptance controller. It is NOT a Linux manager,
// durable enrollment store, dashboard, production issuer, or persistence test.
// Importing this package performs no work. Only explicit Start, StartSelected or StartExpanded
// calls create disposable authority and two loopback listeners. The caller must
// obtain the exact acceptance gate approval before either or endpoint identity.
package fixture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsacceptance/profile"
)

const (
	MaxFrames     = 64
	MaxChallenges = 16
	MaxRequests   = 4096
	MaxLifetime   = 45 * time.Minute
)

var (
	ErrFixture  = errors.New("disposable Windows acceptance fixture unavailable")
	ErrApproval = errors.New("fixture approval does not match the pending identity")
)

// Fixture is an opaque redacted handle. Secret returns only a callback-owned
// temporary copy; callers must never print, persist, or pass it through args or
// environment. No private-key export or OS certificate-store API is provided.
type Fixture struct{ state *state }

type state struct {
	mu                           sync.Mutex
	ctx                          context.Context
	cancel                       context.CancelFunc
	now                          func() time.Time
	selection                    profile.Selection
	signed                       *signedhttp.Verifier
	inventory                    profile.Observation
	telemetryProgress            TelemetryObservation
	expanded                     bool
	extensions                   profile.ExtensionObservation
	lastEventsCollected          time.Time
	lastVolumesCollected         time.Time
	lastProcessCollected         time.Time
	lastNetworkCollected         time.Time
	bootstrap                    enrollmentclient.Bootstrap
	engine                       *enrollmentstate.Engine
	issuer                       *enrollmentissuer.Issuer
	server                       tls.Certificate
	clientRoots                  *x509.CertPool
	issuerCert                   *x509.Certificate
	secret                       []byte
	publicKey                    []byte
	issued                       enrollmentcrypto.VerifiedCertificate
	challenges                   map[string]challenge
	servers                      []*http.Server
	listeners                    []net.Listener
	closeDone                    chan struct{}
	closeErr                     error
	slots                        chan struct{}
	closed, unavailable          bool
	requests, frames, duplicates uint64
	unavailableRequests          uint64
	lastReceipt                  lanstore.Receipt
	lastDigest                   [32]byte
	lastGenerated                time.Time
	lastWindowsGeneration        string
	lastWindowsCollected         time.Time
}

type challenge struct {
	context enrollmentcrypto.ChallengeContext
	purpose string
}

// Evidence contains bounded metadata only. A received frame establishes this
// protocol peer's validation, not native OS origin, Linux persistence, or UI
// acceptance. The native controller must independently establish its execution.
type Evidence struct {
	State               enrollmentstate.State        `json:"state"`
	Platform            string                       `json:"platform"`
	CollectionProfile   string                       `json:"collectionProfile"`
	Transport           string                       `json:"transport"`
	Inventory           profile.Observation          `json:"inventory"`
	Extensions          profile.ExtensionObservation `json:"extensions"`
	Telemetry           TelemetryObservation         `json:"telemetry"`
	Frames              uint64                       `json:"frames"`
	LastSequence        uint64                       `json:"lastSequence"`
	DuplicateReceipts   uint64                       `json:"duplicateReceipts"`
	Requests            uint64                       `json:"requests"`
	UnavailableRequests uint64                       `json:"unavailableRequests"`
	Unavailable         bool                         `json:"unavailable"`
	Closed              bool                         `json:"closed"`
}

func (Fixture) String() string               { return "windowsacceptance.fixture{material:redacted,nonDurable:true}" }
func (f Fixture) GoString() string           { return f.String() }
func (f Fixture) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, f.String()) }
func (Fixture) MarshalJSON() ([]byte, error) {
	return []byte(`{"materialRedacted":true,"durable":false}`), nil
}
func (f Fixture) MarshalText() ([]byte, error) { return []byte(f.String()), nil }
func (f Fixture) LogValue() slog.Value         { return slog.StringValue(f.String()) }

// Start is deliberately not called by init, default tests, or automatic native
// tests. It creates no files, service, account, ACL, firewall rule or system trust.
// TLS is always 1.3, both listeners are IPv4 loopback, and their routes are fixed.
// The fixture closes on cancellation or after MaxLifetime, whichever comes first.
func Start(ctx context.Context) (*Fixture, error) {
	return StartSelected(ctx, profile.BasicTLS())
}

// StartSelected is an explicit manual-only operation under the caller's exact
// profile and transport approval. HTTP is admitted only for Windows inventory;
// it has no TLS fallback and provides no confidentiality or server authentication.
func StartSelected(ctx context.Context, selection profile.Selection) (*Fixture, error) {
	return startSelected(ctx, selection, false)
}

// StartExpanded is a separately authorized manual-only peer for all four Windows
// inventory extensions. It does not change any old selection or enrollment wire.
func StartExpanded(ctx context.Context, selection profile.Selection) (*Fixture, error) {
	if !selection.Inventory() {
		return nil, ErrFixture
	}
	return startSelected(ctx, selection, true)
}
func startSelected(ctx context.Context, selection profile.Selection, expanded bool) (*Fixture, error) {
	if ctx == nil || ctx.Err() != nil || selection.Validate() != nil {
		return nil, ErrFixture
	}
	enrollment, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrFixture
	}
	agent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = enrollment.Close()
		return nil, ErrFixture
	}
	scheme := "https://"
	if selection.HTTPTest() {
		scheme = "http://"
	}
	f, err := newFixtureSelected(ctx, scheme+enrollment.Addr().String(), scheme+agent.Addr().String(), time.Now, selection)
	if err != nil {
		_ = enrollment.Close()
		_ = agent.Close()
		return nil, ErrFixture
	}
	f.state.expanded = expanded
	listeners := make([]net.Listener, 0, 2)
	for i, l := range []net.Listener{enrollment, agent} {
		agentListener := i == 1
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.state.server}}
		if agentListener {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = f.state.clientRoots
		}
		srv := &http.Server{
			Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(w, r, agentListener) }),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
			IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192,
			ErrorLog:    log.New(io.Discard, "", 0),
			BaseContext: func(net.Listener) context.Context { return f.state.ctx },
		}
		f.state.servers = append(f.state.servers, srv)
		var listener net.Listener = &limitedListener{Listener: l, slots: make(chan struct{}, 8)}
		if !selection.HTTPTest() {
			listener = tls.NewListener(listener, cfg)
		}
		listeners = append(listeners, listener)
	}
	// Publish the complete immutable server list before any goroutine can close
	// the fixture. A failed first Serve cannot race the second server's setup.
	f.state.listeners = listeners
	for i, srv := range f.state.servers {
		listener := listeners[i]
		go func() {
			if e := srv.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
				_ = f.Close()
			}
		}()
	}
	go func() { <-f.state.ctx.Done(); _ = f.Close() }()
	return f, nil
}

// newFixture is also used by synthetic handler tests with a fake clock. Those
// tests create explicitly disposable in-memory keys but never listen or invoke
// collectors, protected endpoint state, native ACLs, or services.
func newFixture(ctx context.Context, enrollmentOrigin, agentOrigin string, now func() time.Time) (*Fixture, error) {
	return newFixtureSelected(ctx, enrollmentOrigin, agentOrigin, now, profile.BasicTLS())
}

func newFixtureSelected(ctx context.Context, enrollmentOrigin, agentOrigin string, now func() time.Time, selection profile.Selection) (*Fixture, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || selection.Validate() != nil || !validOrigin(enrollmentOrigin, selection) || !validOrigin(agentOrigin, selection) || enrollmentOrigin == agentOrigin {
		return nil, ErrFixture
	}
	issuer, server, err := newDisposableAuthority(now())
	if err != nil {
		return nil, ErrFixture
	}
	s := &state{now: now, selection: selection, inventory: profile.ZeroObservation(), extensions: profile.ZeroExtensionObservation(), issuer: issuer, server: server, challenges: make(map[string]challenge), slots: make(chan struct{}, 2), closeDone: make(chan struct{})}
	s.ctx, s.cancel = context.WithTimeout(ctx, MaxLifetime)
	f := &Fixture{state: s}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	manager, e1 := randomID("manager_")
	invitation, e2 := randomID("invite_")
	request, e3 := randomID("request_")
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, ErrFixture
	}
	serverCA := publicPEM(issuer.RootDER())
	if selection.HTTPTest() {
		serverCA = ""
	}
	s.bootstrap = enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: manager, Profile: selection.Transport, EnrollmentOrigin: enrollmentOrigin, AgentOrigin: agentOrigin, CollectionProfile: selection.CollectionProfile, InvitationID: invitation, ServerCAPEM: serverCA, IssuerRootPEM: publicPEM(issuer.RootDER()), IssuerPEM: publicPEM(issuer.IssuerDER())}
	s.issuerCert, err = x509.ParseCertificate(issuer.IssuerDER())
	if err != nil {
		return nil, ErrFixture
	}
	s.clientRoots = x509.NewCertPool()
	s.clientRoots.AddCert(s.issuerCert)
	if selection.HTTPTest() {
		s.signed, err = signedhttp.New(signedhttp.Config{Origin: agentOrigin, Path: signedhttp.WindowsPath, Registry: fixtureAuthorizer{s}})
		if err != nil {
			return nil, ErrFixture
		}
	}
	binding := enrollmentstate.Binding{InstanceID: manager, Origin: enrollmentOrigin, Profile: selection.Transport, CollectionProfile: selection.CollectionProfile, IssuerFingerprint: issuer.Fingerprint()}
	cfg := enrollmentstate.DefaultConfig(binding)
	cfg.RecordLimit = 1
	cfg.InvitationLimit = 1
	cfg.PendingLimit = 1
	s.engine, err = enrollmentstate.New(cfg)
	if err != nil {
		return nil, ErrFixture
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return nil, ErrFixture
	}
	s.secret = []byte(base64.RawURLEncoding.EncodeToString(secret[:]))
	clear(secret[:])
	hash, err := enrollmentcrypto.InvitationHash(string(s.secret))
	if err != nil {
		return nil, ErrFixture
	}
	_, err = s.engine.CreateInvitation(s.ctx, enrollmentstate.CreateCommand{InvitationID: invitation, RequestID: request, InvitationHash: hex.EncodeToString(hash[:]), Platform: "windows", Now: now().Unix()})
	clear(hash[:])
	if err != nil {
		return nil, ErrFixture
	}
	ok = true
	return f, nil
}

func validOrigin(origin string, selection profile.Selection) bool {
	u, err := url.Parse(origin)
	scheme := "https"
	if selection.HTTPTest() {
		scheme = "http"
	}
	if err != nil || u.Scheme != scheme || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || origin != scheme+"://"+u.Host {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == u.Port() && u.Host == net.JoinHostPort("127.0.0.1", u.Port())
}

func (f *Fixture) Bootstrap() enrollmentclient.Bootstrap {
	if f == nil || f.state == nil {
		return enrollmentclient.Bootstrap{}
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	return f.state.bootstrap
}

func (f *Fixture) Secret(ctx context.Context) ([]byte, error) {
	if f == nil || f.state == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrFixture
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || len(s.secret) != 43 {
		return nil, ErrFixture
	}
	return bytes.Clone(s.secret), nil
}

func (f *Fixture) Snapshot() enrollmentstate.Snapshot {
	if f == nil || f.state == nil {
		return enrollmentstate.Snapshot{}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.snapshot()
	return v
}

func (s *state) snapshot() (enrollmentstate.Snapshot, error) {
	if s.engine == nil {
		return enrollmentstate.Snapshot{}, ErrFixture
	}
	return s.engine.Get(s.bootstrap.InvitationID)
}

func (f *Fixture) Evidence() Evidence {
	if f == nil || f.state == nil {
		return Evidence{Closed: true, Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation()}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.snapshot()
	return Evidence{State: v.State, Platform: v.Platform, CollectionProfile: v.Binding.CollectionProfile, Transport: s.selection.Transport, Inventory: s.inventory, Extensions: s.extensions, Telemetry: s.telemetryProgress, Frames: s.frames, LastSequence: s.lastReceipt.Sequence, DuplicateReceipts: s.duplicates, Requests: s.requests, UnavailableRequests: s.unavailableRequests, Unavailable: s.unavailable, Closed: s.closed}
}

// ToggleUnavailable models a scoped transport outage; it never changes the
// lifecycle clock, pending deadlines, identity, counters, or receipt timestamps.
func (f *Fixture) ToggleUnavailable(unavailable bool) {
	if f == nil || f.state == nil {
		return
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unavailable = unavailable
}

// Approve is a local controller operation with no HTTP route. Both values must
// come from the independently observed endpoint display, not copied blindly from
// Snapshot. It issues a disposable one-hour client certificate in memory only.
func (f *Fixture) Approve(expectedFingerprint, expectedComparison string) error {
	if f == nil || f.state == nil {
		return ErrApproval
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.snapshot()
	if e != nil || s.closed || s.ctx.Err() != nil || v.State != enrollmentstate.ClaimedPending || expectedFingerprint == "" || expectedComparison == "" || v.Claim.KeyFingerprint != expectedFingerprint || v.Claim.ComparisonCode != expectedComparison {
		return ErrApproval
	}
	device, e1 := randomID("agent_")
	approveID, e2 := randomID("request_")
	intentID, e3 := randomID("intent_")
	intentRequest, e4 := randomID("request_")
	commitID, e5 := randomID("request_")
	serial, e6 := randomID("")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil {
		return ErrFixture
	}
	now := s.now().UTC()
	v, e = s.engine.Approve(s.ctx, enrollmentstate.ApproveCommand{Control: control(v, approveID, now), DeviceID: device, KeyFingerprint: expectedFingerprint})
	if e != nil {
		return ErrApproval
	}
	v, e = s.engine.BeginIssuance(s.ctx, enrollmentstate.IntentCommand{Control: control(v, intentRequest, now), IntentID: intentID, SerialHex: serial, TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Add(-30 * time.Second).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	if e != nil {
		return ErrFixture
	}
	intent, e := s.engine.SigningIntent(v.InvitationID, now.Unix())
	if e != nil {
		return ErrFixture
	}
	issued, e := s.issuer.Sign(s.ctx, intent, now)
	if e != nil {
		return ErrFixture
	}
	if _, e = s.engine.CommitIssued(s.ctx, control(v, commitID, now), issued); e != nil {
		return ErrFixture
	}
	s.issued = issued
	return nil
}

func control(v enrollmentstate.Snapshot, request string, now time.Time) enrollmentstate.Control {
	return enrollmentstate.Control{InvitationID: v.InvitationID, RequestID: request, ExpectedRevision: v.Revision, Now: now.Unix()}
}

func (f *Fixture) Close() error {
	if f == nil || f.state == nil {
		return nil
	}
	s := f.state
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	servers := append([]*http.Server(nil), s.servers...)
	listeners := append([]net.Listener(nil), s.listeners...)
	clear(s.secret)
	s.secret = nil
	s.challenges = nil
	s.issuer = nil
	// Drop signing authority. A TLS handshake may still hold a shared immutable
	// key while its connection is closing, so do not overwrite that key in place.
	// Go/crypto may retain transient copies; this is not secure memory erasure.
	s.server = tls.Certificate{}
	s.mu.Unlock()
	var err error
	// Also close the listeners directly: cancellation may win before Serve has
	// registered its listener, and Close must not return with that port open.
	for _, listener := range listeners {
		if e := listener.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			err = ErrFixture
		}
	}
	for _, srv := range servers {
		if e := srv.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			err = ErrFixture
		}
	}
	s.mu.Lock()
	s.closeErr = err
	close(s.closeDone)
	s.mu.Unlock()
	return err
}

func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once  sync.Once
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, slots: l.slots}, nil
		default:
			_ = c.Close()
		}
	}
}
func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(func() { <-c.slots }); return e }
