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
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowsnetworkcontextwire"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

type networkContextSender struct {
	mu       sync.Mutex
	material Material
	storage  windowsnetworkcontext.Storage
	state    *windowsnetworkcontext.State
	client   *http.Client
	now      func() time.Time
	collect  func(context.Context) (windowsnetworkcontext.Capture, error)
	current  func() bool
	closed   bool
}

func (*networkContextSender) String() string {
	return "Windows route and interface-counter context sender (contents redacted)"
}
func (s *networkContextSender) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*networkContextSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}

type networkContextReport struct {
	Status         string
	Sequence       uint64
	Operations     int
	RetriedPending bool
}

func openWindowsNetworkContextSender(m Material, primary *lanclientstate.State) (*networkContextSender, error) {
	if !m.config.windowsInventory() {
		return nil, nil
	}
	if !m.valid() || primary == nil {
		return nil, ErrConfiguration
	}
	used, e := primary.WindowsNetworkContextUsed()
	if e != nil {
		return nil, ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return nil, ErrState
	}
	st, e := windowsstate.Open(windowsNetworkContextDirectory(m), windowsNetworkContextOptions(sid, false))
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
	s, e := newNetworkContextSender(m, st, func() time.Time { return time.Now().UTC() }, windowsnetworkcontext.Collect)
	if e != nil {
		st.Close()
		return nil, e
	}
	return s, nil
}
func newNetworkContextSender(m Material, st windowsnetworkcontext.Storage, now func() time.Time, collect func(context.Context) (windowsnetworkcontext.Capture, error)) (*networkContextSender, error) {
	return newNetworkContextSenderWithAuthority(m, st, now, collect, func() bool { return currentWindowsContextMaterial(m, Load) })
}
func newNetworkContextSenderWithAuthority(m Material, st windowsnetworkcontext.Storage, now func() time.Time, collect func(context.Context) (windowsnetworkcontext.Capture, error), current func() bool) (*networkContextSender, error) {
	if !m.valid() || !m.config.windowsInventory() || st == nil || now == nil || collect == nil || current == nil {
		return nil, ErrConfiguration
	}
	state, e := windowsnetworkcontext.OpenState(st, m.config.AgentID, m.binding)
	if e != nil {
		return nil, ErrState
	}
	s := &networkContextSender{material: m, storage: st, state: state, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now, collect: collect, current: current}
	if _, e = s.consent(); e != nil {
		return nil, e
	}
	return s, nil
}

// validMaterial also observes the sender's trusted current clock. In production
// this is the wall clock; fixtures can advance it without native collection.
func (s *networkContextSender) validMaterial() bool {
	if !s.material.valid() || s.now == nil || s.current == nil || !s.current() {
		return false
	}
	leaf, e := x509.ParseCertificate(s.material.certificate.Certificate[0])
	now := s.now().UTC()
	return e == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func (s *networkContextSender) consent() (windowsnetworkcontext.Consent, error) {
	if !s.validMaterial() {
		return windowsnetworkcontext.Consent{}, ErrConfiguration
	}
	raw, e := s.storage.Read("consent.json")
	if e != nil {
		return windowsnetworkcontext.Consent{}, ErrState
	}
	c, e := windowsnetworkcontext.DecodeConsent(raw)
	if e != nil || c.SenderBinding != s.material.binding {
		return windowsnetworkcontext.Consent{}, ErrState
	}
	if !s.validMaterial() {
		return windowsnetworkcontext.Consent{}, ErrConfiguration
	}
	return c, nil
}
func (s *networkContextSender) Close() error {
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
func (s *networkContextSender) Burst(parent context.Context) (networkContextReport, error) {
	out := networkContextReport{Status: "disabled"}
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
	ctx, cancel := context.WithTimeout(parent, windowsnetworkcontext.BurstTimeout)
	defer cancel()
	c, e := s.consent()
	if e != nil {
		return out, e
	}
	out.Sequence = s.state.Floor()
	out.RetriedPending = s.state.Pending()
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
	if status == "capture_due" {
		current, e := s.consent()
		if e != nil {
			return out, e
		}
		if current != c {
			return out, ErrState
		}
		if _, e = s.state.Reserve(c, s.now().UTC()); e != nil {
			return out, ErrState
		}
		out.Sequence = s.state.Floor()
		// Durable reservation can block. Expiry after it consumes no new native
		// read and leaves the claimed floor for fail-closed restart diagnosis.
		if !s.validMaterial() {
			return out, ErrConfiguration
		}
		current, e = s.consent()
		if e != nil || current != c {
			return out, ErrState
		}
		captureCtx, stop := context.WithTimeout(ctx, windowsnetworkcontext.CaptureTimeout)
		capture, sourceErr := s.collect(captureCtx)
		stop()
		// The frozen failed attempt is retained even after cancellation. No later
		// retry is allowed to call the source for this consumed sequence.
		if e = s.state.Finish(capture, sourceErr, s.now().UTC()); e != nil {
			return out, ErrState
		}
		if !s.validMaterial() {
			return out, ErrConfiguration
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		raw, status, e = s.state.Next(c, s.now().UTC())
		if e != nil {
			return out, ErrState
		}
		out.Status = status
	}
	if len(raw) == 0 {
		return out, nil
	}
	for out.Operations < windowsnetworkcontext.MaxOperations {
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
			m, _ := windowsnetworkcontext.DecodeMessage(raw)
			if m.Operation == "failure" {
				out.Status = "source_failed"
			}
			return out, nil
		}
	}
	out.Status = "pending_retained"
	return out, nil
}
func (s *networkContextSender) exchange(ctx context.Context, body []byte, c windowsnetworkcontext.Consent) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, e := s.consent()
	if e != nil {
		return nil, e
	}
	if current != c {
		return nil, windowsnetworkcontext.ErrTransport
	}
	m, e := windowsnetworkcontext.DecodeMessage(body)
	if e != nil || m.Consent != c {
		return nil, ErrState
	}
	var request *http.Request
	if s.material.config.Profile == "http-test" {
		request, e = windowsnetworkcontextwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, s.material.certificate, m.Operation, m.WireSequence(), s.now().UTC(), body)
	} else {
		request, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+windowsnetworkcontextwire.PathPrefix+m.Operation, bytes.NewReader(body))
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
		return nil, windowsnetworkcontext.ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, windowsnetworkcontext.ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2049))
	if e != nil || len(raw) > 2048 {
		return nil, windowsnetworkcontext.ErrTransport
	}
	if !s.validMaterial() {
		return nil, ErrConfiguration
	}
	receipt, e := windowsnetworkcontext.DecodeReceipt(raw, body)
	now := s.now().UTC()
	if e != nil || receipt.ReceivedAt.After(now.Add(30*time.Second)) || receipt.ReceivedAt.Before(c.ChangedAt) {
		return nil, windowsnetworkcontext.ErrTransport
	}
	if m.Manifest != nil && receipt.ReceivedAt.Before(m.Manifest.CaptureFinishedAt) || m.AttemptedAt != nil && receipt.ReceivedAt.Before(*m.AttemptedAt) {
		return nil, windowsnetworkcontext.ErrTransport
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, e = s.consent()
	if e != nil || current != c {
		return nil, ErrState
	}
	return raw, nil
}
func runWindowsNetworkContextAttempt(ctx context.Context, s *networkContextSender, report *Report) error {
	if s == nil {
		return nil
	}
	out, e := s.Burst(ctx)
	report.WindowsNetworkContextStatus = out.Status
	report.WindowsNetworkContextSequence = out.Sequence
	report.WindowsNetworkContextOperations = uint8(out.Operations)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e == windowsnetworkcontext.ErrTransport || errors.Is(e, context.DeadlineExceeded) {
		return nil
	}
	return e
}
