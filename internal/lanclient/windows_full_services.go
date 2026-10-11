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
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullserviceswire"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

type fullServicesSender struct {
	mu       sync.Mutex
	material Material
	storage  windowsfullservices.Storage
	state    *windowsfullservices.State
	client   *http.Client
	now      func() time.Time
	collect  func(context.Context) (windowsfullservices.Capture, error)
	closed   bool
}

func (*fullServicesSender) String() string {
	return "Windows complete services sender (contents redacted)"
}
func (s *fullServicesSender) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*fullServicesSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}

type fullServicesReport struct {
	Status         string
	Sequence       uint64
	Operations     int
	RetriedPending bool
}

func openWindowsFullServicesSender(m Material, primary *lanclientstate.State) (*fullServicesSender, error) {
	if !m.config.windowsInventory() {
		return nil, nil
	}
	if !m.valid() || primary == nil {
		return nil, ErrConfiguration
	}
	used, e := primary.WindowsFullServicesUsed()
	if e != nil {
		return nil, ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return nil, ErrState
	}
	st, e := windowsstate.Open(windowsFullServicesDirectory(m), windowsFullServicesOptions(sid, false))
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
	s, e := newFullServicesSender(m, st, func() time.Time { return time.Now().UTC() }, windowsfullservices.Collect)
	if e != nil {
		st.Close()
		return nil, e
	}
	return s, nil
}
func newFullServicesSender(m Material, st windowsfullservices.Storage, now func() time.Time, collect func(context.Context) (windowsfullservices.Capture, error)) (*fullServicesSender, error) {
	if !m.valid() || !m.config.windowsInventory() || st == nil || now == nil || collect == nil {
		return nil, ErrConfiguration
	}
	state, e := windowsfullservices.OpenState(st, m.config.AgentID, m.binding)
	if e != nil {
		return nil, ErrState
	}
	s := &fullServicesSender{material: m, storage: st, state: state, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now, collect: collect}
	if _, e = s.consent(); e != nil {
		return nil, e
	}
	return s, nil
}

// validMaterial also observes the sender's trusted current clock. In production
// this is the wall clock; fixtures can advance it without native collection.
func (s *fullServicesSender) validMaterial() bool {
	if !s.material.valid() || s.now == nil {
		return false
	}
	leaf, e := x509.ParseCertificate(s.material.certificate.Certificate[0])
	now := s.now().UTC()
	return e == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func (s *fullServicesSender) consent() (windowsfullservices.Consent, error) {
	if !s.validMaterial() {
		return windowsfullservices.Consent{}, ErrConfiguration
	}
	raw, e := s.storage.Read("consent.json")
	if e != nil {
		return windowsfullservices.Consent{}, ErrState
	}
	c, e := windowsfullservices.DecodeConsent(raw)
	if e != nil || c.SenderBinding != s.material.binding {
		return windowsfullservices.Consent{}, ErrState
	}
	if !s.validMaterial() {
		return windowsfullservices.Consent{}, ErrConfiguration
	}
	return c, nil
}
func (s *fullServicesSender) Close() error {
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
func (s *fullServicesSender) Burst(parent context.Context) (fullServicesReport, error) {
	out := fullServicesReport{Status: "disabled"}
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
	ctx, cancel := context.WithTimeout(parent, windowsfullservices.BurstTimeout)
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
		captureCtx, stop := context.WithTimeout(ctx, windowsfullservices.CaptureTimeout)
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
	for out.Operations < windowsfullservices.MaxOperations {
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
			m, _ := windowsfullservices.DecodeMessage(raw)
			if m.Operation == "failure" {
				out.Status = "source_failed"
			}
			return out, nil
		}
	}
	out.Status = "pending_retained"
	return out, nil
}
func (s *fullServicesSender) exchange(ctx context.Context, body []byte, c windowsfullservices.Consent) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, e := s.consent()
	if e != nil {
		return nil, e
	}
	if current != c {
		return nil, windowsfullservices.ErrTransport
	}
	m, e := windowsfullservices.DecodeMessage(body)
	if e != nil || m.Consent != c {
		return nil, ErrState
	}
	var request *http.Request
	if s.material.config.Profile == "http-test" {
		request, e = windowsfullserviceswire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, s.material.certificate, m.Operation, m.WireSequence(), s.now().UTC(), body)
	} else {
		request, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+windowsfullserviceswire.PathPrefix+m.Operation, bytes.NewReader(body))
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
		return nil, windowsfullservices.ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, windowsfullservices.ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2049))
	if e != nil || len(raw) > 2048 {
		return nil, windowsfullservices.ErrTransport
	}
	if !s.validMaterial() {
		return nil, ErrConfiguration
	}
	receipt, e := windowsfullservices.DecodeReceipt(raw, body)
	now := s.now().UTC()
	if e != nil || receipt.ReceivedAt.After(now.Add(30*time.Second)) || receipt.ReceivedAt.Before(c.ChangedAt) {
		return nil, windowsfullservices.ErrTransport
	}
	if m.Manifest != nil && receipt.ReceivedAt.Before(m.Manifest.CaptureFinishedAt) || m.AttemptedAt != nil && receipt.ReceivedAt.Before(*m.AttemptedAt) {
		return nil, windowsfullservices.ErrTransport
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return raw, nil
}
func runWindowsFullServicesAttempt(ctx context.Context, s *fullServicesSender, report *Report) error {
	if s == nil {
		return nil
	}
	out, e := s.Burst(ctx)
	report.WindowsFullServicesStatus = out.Status
	report.WindowsFullServicesSequence = out.Sequence
	report.WindowsFullServicesOperations = uint8(out.Operations)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e == windowsfullservices.ErrTransport || errors.Is(e, context.DeadlineExceeded) {
		return nil
	}
	return e
}
