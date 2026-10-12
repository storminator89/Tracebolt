package lanclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsusersoftware"
	"localrmm/internal/windowsusersoftwarelocal"
	"localrmm/internal/windowsusersoftwarewire"
)

type userSoftwareSender struct {
	mu             sync.Mutex
	material       Material
	storage        windowsusersoftware.Storage
	state          *windowsusersoftware.State
	client         *http.Client
	now            func() time.Time
	active         *userSoftwareChallenge
	receiverFailed bool
	closed         bool
}

func (*userSoftwareSender) String() string {
	return "Windows selected-account software sender (contents redacted)"
}
func (s *userSoftwareSender) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*userSoftwareSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}

type userSoftwareReport struct {
	Status         string
	Sequence       uint64
	Operations     int
	RetriedPending bool
}

func openWindowsUserSoftwareSender(m Material, primary *lanclientstate.State) (*userSoftwareSender, error) {
	if !m.config.windowsInventory() {
		return nil, nil
	}
	if !m.valid() || primary == nil {
		return nil, ErrConfiguration
	}
	used, e := primary.WindowsUserSoftwareUsed()
	if e != nil {
		return nil, ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return nil, ErrState
	}
	st, e := windowsstate.Open(windowsUserSoftwareDirectory(m), windowsUserSoftwareOptions(sid, false))
	if errors.Is(e, os.ErrNotExist) {
		if used {
			return nil, ErrState
		}
		return nil, nil
	}
	if e == nil && !used {
		st.Close()
		return nil, ErrState
	}
	if e != nil {
		return nil, ErrState
	}
	s, e := newUserSoftwareSender(m, st, func() time.Time { return time.Now().UTC() })
	if e != nil {
		st.Close()
		return nil, e
	}
	return s, nil
}
func newUserSoftwareSender(m Material, st windowsusersoftware.Storage, now func() time.Time) (*userSoftwareSender, error) {
	if !m.valid() || !m.config.windowsInventory() || st == nil || now == nil {
		return nil, ErrConfiguration
	}
	state, e := windowsusersoftware.OpenState(st, m.config.AgentID, m.binding)
	if e != nil {
		return nil, ErrState
	}
	s := &userSoftwareSender{material: m, storage: st, state: state, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now}
	if _, e = s.consent(); e != nil {
		return nil, e
	}
	return s, nil
}

// validMaterial also observes the sender's trusted current clock. In production
// this is the wall clock; fixtures can advance it without native collection.
func (s *userSoftwareSender) validMaterial() bool {
	if !s.material.valid() || s.now == nil {
		return false
	}
	leaf, e := x509.ParseCertificate(s.material.certificate.Certificate[0])
	now := s.now().UTC()
	return e == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func (s *userSoftwareSender) consent() (windowsusersoftware.Consent, error) {
	if !s.validMaterial() {
		return windowsusersoftware.Consent{}, ErrConfiguration
	}
	raw, e := s.storage.Read("consent.json")
	if e != nil {
		return windowsusersoftware.Consent{}, ErrState
	}
	c, e := windowsusersoftware.DecodeConsent(raw)
	if e != nil || c.SenderBinding != s.material.binding {
		return windowsusersoftware.Consent{}, ErrState
	}
	if !s.validMaterial() {
		return windowsusersoftware.Consent{}, ErrConfiguration
	}
	return c, nil
}
func (s *userSoftwareSender) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.client.CloseIdleConnections()
	return s.state.Close()
}
func (s *userSoftwareSender) Burst(parent context.Context) (userSoftwareReport, error) {
	out := userSoftwareReport{Status: "disabled"}
	if s == nil {
		return out, nil
	}
	if parent == nil {
		return out, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return out, ErrState
	}
	ctx, cancel := context.WithTimeout(parent, windowsusersoftware.BurstTimeout)
	defer cancel()
	c, e := s.consent()
	if e != nil {
		return out, e
	}
	out.Sequence = s.state.Floor()
	out.RetriedPending = s.state.Pending()
	// A live foreground challenge owns the independent capture state. In
	// particular Next must not recover its reservation while the helper reads.
	if s.active != nil {
		out.Status = "foreground_pending"
		return out, nil
	}
	// Scope synchronization contains no inventory rows. A stopped endpoint cannot
	// announce a local disable until it next runs. Every unchanged body retries
	// exactly; its original acceptance time is retained by the manager.
	raw, needed, e := s.state.Scope(c)
	if e != nil {
		return out, ErrState
	}
	if needed {
		receipt, e := s.exchange(ctx, raw, c)
		out.Operations++
		if e != nil {
			return out, e
		}
		if s.state.AcknowledgeScope(raw, receipt, s.now().UTC()) != nil {
			return out, ErrState
		}
	}
	if !c.Enabled {
		return out, nil
	}
	raw, status, e := s.state.Next(c, s.now().UTC())
	if e != nil {
		return out, ErrState
	}
	out.Status = status

	if len(raw) == 0 {
		if s.receiverFailed {
			out.Status = "receiver_unavailable"
		}
		return out, nil
	}
	for out.Operations < windowsusersoftware.MaxOperations {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		current, e := s.consent()
		if e != nil {
			return out, e
		}
		if current != c {
			out.Status = "disabled"
			return out, nil
		}
		raw, status, e = s.state.Next(c, s.now().UTC())
		if e != nil {
			return out, ErrState
		}
		out.Status = status
		if len(raw) == 0 {
			return out, nil
		}
		receipt, e := s.exchange(ctx, raw, c)
		out.Operations++
		if e != nil {
			out.Status = "pending_retained"
			return out, e
		}
		if s.state.Acknowledge(raw, receipt, s.now().UTC()) != nil {
			return out, ErrState
		}
		if !s.state.Pending() {
			out.Status = "complete"
			m, _ := windowsusersoftware.DecodeMessage(raw)
			if m.Operation == "failure" {
				out.Status = "source_failed"
			}
			return out, nil
		}
	}
	out.Status = "pending_retained"
	return out, nil
}
func (s *userSoftwareSender) exchange(ctx context.Context, body []byte, c windowsusersoftware.Consent) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, e := s.consent()
	if e != nil {
		return nil, e
	}
	if current != c {
		return nil, windowsusersoftware.ErrTransport
	}
	m, e := windowsusersoftware.DecodeMessage(body)
	if e != nil || m.Consent != c {
		return nil, ErrState
	}
	var request *http.Request
	if s.material.config.Profile == "http-test" {
		request, e = windowsusersoftwarewire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, s.material.certificate, m.Operation, m.WireSequence(), s.now().UTC(), body)
	} else {
		request, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+windowsusersoftwarewire.PathPrefix+m.Operation, bytes.NewReader(body))
		if e == nil {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return nil, ErrConfiguration
	}
	if !s.validMaterial() {
		return nil, ErrConfiguration
	}
	response, e := s.client.Do(request)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, windowsusersoftware.ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, windowsusersoftware.ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2049))
	if e != nil || len(raw) > 2048 {
		return nil, windowsusersoftware.ErrTransport
	}
	if !s.validMaterial() {
		return nil, ErrConfiguration
	}
	receipt, e := windowsusersoftware.DecodeReceipt(raw, body)
	now := s.now().UTC()
	if e != nil || receipt.ReceivedAt.After(now.Add(30*time.Second)) || receipt.ReceivedAt.Before(c.ChangedAt) {
		return nil, windowsusersoftware.ErrTransport
	}
	if m.Manifest != nil && receipt.ReceivedAt.Before(m.Manifest.CaptureFinishedAt) || m.AttemptedAt != nil && receipt.ReceivedAt.Before(*m.AttemptedAt) {
		return nil, windowsusersoftware.ErrTransport
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return raw, nil
}
func runWindowsUserSoftwareAttempt(ctx context.Context, s *userSoftwareSender, report *Report) error {
	if s == nil {
		return nil
	}
	out, e := s.Burst(ctx)
	report.WindowsUserSoftwareStatus = out.Status
	report.WindowsUserSoftwareSequence = out.Sequence
	report.WindowsUserSoftwareOperations = uint8(out.Operations)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e == windowsusersoftware.ErrTransport || errors.Is(e, context.DeadlineExceeded) {
		return nil
	}
	return e
}

// The sole native pipe connection supplies Peer from held OS handles. No helper
// field establishes account authority. Only this adapter binds it to the current
// device identity and independently consented capture state.
type userSoftwareChallenge struct {
	peer       windowsusersoftwarelocal.Peer
	challenge  windowsusersoftwarelocal.Challenge
	consent    windowsusersoftware.Consent
	beganAt    time.Time
	reservedAt time.Time
}

func (s *userSoftwareSender) Begin(ctx context.Context, peer windowsusersoftwarelocal.Peer, nonce string) (windowsusersoftwarelocal.Challenge, error) {
	zero := windowsusersoftwarelocal.Challenge{}
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, windowsusersoftware.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active != nil || peer.ProcessID == 0 || peer.SessionID == 0 {
		return zero, windowsusersoftware.ErrUnavailable
	}
	c, e := s.consent()
	if e != nil || !c.Enabled {
		return zero, windowsusersoftware.ErrUnavailable
	}
	now := s.now().UTC()
	_, status, e := s.state.Next(c, now)
	if e != nil || s.state.Pending() || status != "awaiting_foreground_capture" {
		return zero, windowsusersoftware.ErrUnavailable
	}
	id, e := windowsusersoftware.AccountContextID(s.material.config.AgentID, peer.SID)
	if e != nil {
		return zero, windowsusersoftware.ErrInvalid
	}
	label := "Selected account " + id[:12]
	if !windowsusersoftware.ValidAccount(id, label, nonce) {
		return zero, windowsusersoftware.ErrInvalid
	}
	challenge := windowsusersoftwarelocal.Challenge{Nonce: nonce, AccountContextID: id, AccountLabel: label, ExpiresAt: now.Add(2 * time.Minute), DeviceID: s.material.config.AgentID, ManagerOrigin: s.material.config.ManagerOrigin, InsecureHTTP: s.material.config.Profile == "http-test"}
	s.active = &userSoftwareChallenge{peer: peer, challenge: challenge, consent: c, beganAt: now}
	return challenge, nil
}

func (s *userSoftwareSender) activeChallenge(ctx context.Context, peer windowsusersoftwarelocal.Peer, challenge windowsusersoftwarelocal.Challenge) (*userSoftwareChallenge, error) {
	if s.closed || ctx == nil || ctx.Err() != nil || s.active == nil || s.active.peer != peer || s.active.challenge != challenge {
		return nil, windowsusersoftware.ErrUnavailable
	}
	a := s.active
	now := s.now().UTC()
	if now.Before(a.beganAt) || !now.Before(a.challenge.ExpiresAt) {
		return nil, windowsusersoftware.ErrExpired
	}
	c, e := s.consent()
	if e != nil || !c.Enabled || c != a.consent {
		return nil, windowsusersoftware.ErrUnavailable
	}
	return a, nil
}

func (s *userSoftwareSender) Reserve(ctx context.Context, peer windowsusersoftwarelocal.Peer, challenge windowsusersoftwarelocal.Challenge) error {
	if s == nil {
		return windowsusersoftware.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.activeChallenge(ctx, peer, challenge)
	if e != nil {
		return e
	}
	if !a.reservedAt.IsZero() {
		return windowsusersoftware.ErrState
	}
	now := s.now().UTC()
	if !now.Add(windowsusersoftware.CaptureTimeout).Before(challenge.ExpiresAt) {
		return windowsusersoftware.ErrExpired
	}
	if _, e = s.state.ReserveCapture(a.consent, challenge.AccountContextID, challenge.AccountLabel, challenge.Nonce, now); e != nil {
		return e
	}
	a.reservedAt = now
	// The consumed sequence survives a slow durable write or changed authority.
	_, e = s.activeChallenge(ctx, peer, challenge)
	if e != nil {
		return e
	}
	if s.now().UTC().Sub(now) >= windowsusersoftware.CaptureTimeout {
		return windowsusersoftware.ErrExpired
	}
	return nil
}

func (s *userSoftwareSender) Submit(ctx context.Context, peer windowsusersoftwarelocal.Peer, challenge windowsusersoftwarelocal.Challenge, capture windowsusersoftware.Capture) error {
	if s == nil {
		return windowsusersoftware.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.activeChallenge(ctx, peer, challenge)
	if e != nil {
		return e
	}
	if a.reservedAt.IsZero() {
		return windowsusersoftware.ErrState
	}
	now := s.now().UTC()
	// Account fields are service-derived, never trusted from the submitted frame.
	capture.AccountContextID = challenge.AccountContextID
	capture.AccountLabel = challenge.AccountLabel
	capture.CaptureNonce = challenge.Nonce
	if capture.StartedAt.Before(a.reservedAt) || capture.FinishedAt.After(now) || now.Sub(a.reservedAt) > windowsusersoftware.CaptureTimeout {
		return windowsusersoftware.ErrExpired
	}
	if e = s.state.Finish(capture, nil, now); e != nil {
		return e
	}
	s.active = nil // Acknowledgement loss cannot reuse the consumed challenge.
	if !s.validMaterial() || ctx.Err() != nil {
		return windowsusersoftware.ErrUnavailable
	}
	return nil
}

func (s *userSoftwareSender) Abort(_ context.Context, peer windowsusersoftwarelocal.Peer, challenge windowsusersoftwarelocal.Challenge) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active == nil {
		return nil
	}
	a := s.active
	if a.peer != peer || a.challenge != challenge {
		return windowsusersoftware.ErrInvalid
	}
	s.active = nil
	if a.reservedAt.IsZero() {
		return nil
	}
	// Cleanup consumes an already-reserved attempt even after the connection or
	// grant expires. It never reads a source, changes consent or transmits data.
	return s.state.Finish(windowsusersoftware.Capture{Reason: "canceled"}, context.Canceled, s.now().UTC())
}

func startWindowsUserSoftwareReceiver(ctx context.Context, s *userSoftwareSender) func() {
	if s == nil {
		return func() {}
	}
	s.mu.Lock()
	c, e := s.consent()
	enabled := e == nil && c.Enabled && !s.closed
	s.mu.Unlock()
	if !enabled {
		return func() {}
	}
	child, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e := windowsusersoftwarelocal.Serve(child, s)
		if e != nil && child.Err() == nil {
			s.mu.Lock()
			s.receiverFailed = true
			s.active = nil // No receiver restart. Next drain recovers any consumed reservation; never a source read.
			s.mu.Unlock()
		}
	}()
	return func() { cancel(); <-done }
}
