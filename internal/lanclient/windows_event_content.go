package lanclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowseventworker"
)

// The existing sender owns this serialized stage and its lifetime. Content is
// never put in sender telemetry or durable pending bytes. Only one exact result
// can occupy this bounded slot until the immutable original request expiry.
var errEventContentRejected = errors.New("windows_event_content_rejected")

type windowsEventContentSender struct {
	material Material
	client   *http.Client
	now      func() time.Time
	local    func(Material) (windowseventrequest.Consent, error)
	metadata func(Material, windowseventrequest.Consent, func(windowseventstate.Storage) error) error
	collect  func(context.Context, windowseventworker.Request) (windowseventcontent.Report, error)
	exchange func(context.Context, string, uint64, []byte) ([]byte, int, error)
	pending  *windowsEventContentPending
}
type windowsEventContentPending struct {
	memory  *journalMemory
	timer   *time.Timer
	done    chan struct{}
	grant   windowseventwire.Grant
	consent windowseventrequest.Consent
	digest  string
}

func (windowsEventContentSender) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("<selected event sender>"))
}
func (windowsEventContentPending) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("<selected event content redacted>"))
}
func (windowsEventContentSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentRedacted":true}`), nil
}
func (windowsEventContentPending) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentRedacted":true}`), nil
}
func openWindowsEventContentSender(m Material) *windowsEventContentSender {
	if !m.config.windowsInventory() {
		return nil
	}
	s := &windowsEventContentSender{material: m, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: func() time.Time { return time.Now().UTC() }, local: readWindowsEventContentLocal, metadata: withWindowsEventReports, collect: windowseventworker.Gather}
	s.exchange = s.request
	return s
}
func (s *windowsEventContentSender) discard() {
	if s == nil || s.pending == nil {
		return
	}
	p := s.pending
	if p.timer != nil {
		if p.timer.Stop() {
			close(p.done)
		} else {
			<-p.done
		}
	}
	p.memory.mu.Lock()
	clear(p.memory.raw)
	p.memory.raw = nil
	p.memory.expired = true
	p.memory.mu.Unlock()
	s.pending = nil
}
func (s *windowsEventContentSender) Close() {
	if s == nil {
		return
	}
	s.discard()
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (p *windowsEventContentPending) startExpiry() {
	p.timer = time.AfterFunc(time.Until(p.grant.Description.ExpiresAt), func() {
		p.memory.mu.Lock()
		clear(p.memory.raw)
		p.memory.raw = nil
		p.memory.expired = true
		p.memory.mu.Unlock()
		close(p.done)
	})
}
func (s *windowsEventContentSender) prune() string {
	if s == nil || s.pending == nil {
		return ""
	}
	p := s.pending
	p.memory.mu.Lock()
	expired := p.memory.expired
	p.memory.mu.Unlock()
	now := s.now().UTC()
	if expired || now.Before(p.grant.ClaimedAt) || !now.Before(p.grant.Description.ExpiresAt) {
		s.discard()
		return "expired"
	}
	c, e := s.local(s.material)
	if e != nil || c != p.consent || !c.Enabled {
		s.discard()
		return "denied"
	}
	policy, e := windowseventrequest.Authorize(p.grant.Description, c, windowsEventContentContext(s.material), now)
	if e != nil || policy != p.grant.PolicyDigest {
		s.discard()
		return "denied"
	}
	return "pending_retained"
}
func (s *windowsEventContentSender) status(ctx context.Context, claim windowseventwire.Claim, status string) {
	body, e := windowseventwire.EncodeStatus(windowseventwire.StatusInput{Claim: claim, LocalStatus: status})
	if e == nil && ctx.Err() == nil {
		_, _, _ = s.exchange(ctx, windowseventwire.StatusPath, claim.Identity.Sequence, body)
	}
}
func (s *windowsEventContentSender) reportCapability(ctx context.Context, c windowseventrequest.Consent) error {
	var body []byte
	local := windowsEventContentContext(s.material)
	e := s.metadata(s.material, c, func(st windowseventstate.Storage) error {
		var e error
		body, e = windowseventstate.StageCapability(st, local, c, s.now().UTC())
		return e
	})
	if e != nil {
		return e
	}
	cap, e := windowseventwire.DecodeCapability(body)
	if e != nil {
		return e
	}
	current, e := s.local(s.material)
	if e != nil || current != c {
		return ErrState
	}
	reply, code, e := s.exchange(ctx, windowseventwire.CapabilityPath, cap.Sequence, body)
	if e != nil {
		return ErrTransport
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusConflict || code == http.StatusGone {
		return errEventContentRejected
	}
	if code != http.StatusOK || !bytes.Equal(reply, body) {
		return ErrTransport
	}
	return s.metadata(s.material, c, func(st windowseventstate.Storage) error {
		return windowseventstate.AcknowledgeCapability(st, local, body)
	})
}
func (s *windowsEventContentSender) Run(ctx context.Context) string {
	if s == nil {
		return "disabled"
	}
	if ctx == nil || ctx.Err() != nil {
		return "unavailable"
	}
	s.prune()
	c, e := s.local(s.material)
	if e != nil {
		s.discard()
		if errors.Is(e, errEventContentDisabled) {
			return "disabled"
		}
		return "denied"
	}
	if !c.Enabled {
		s.discard()
	}
	if e := s.reportCapability(ctx, c); e != nil {
		if errors.Is(e, errEventContentRejected) || errors.Is(e, ErrState) || errors.Is(e, windowseventstate.ErrState) {
			s.discard()
			return "denied"
		}
		if status := s.prune(); status != "" && status != "pending_retained" {
			return status
		}
		return "unavailable"
	}
	if !c.Enabled {
		return "disabled"
	}
	if s.pending != nil {
		return s.deliver(ctx)
	}
	body, _ := windowseventwire.EncodePeek()
	raw, code, e := s.exchange(ctx, windowseventwire.PeekPath, 1, body)
	if e != nil {
		return "unavailable"
	}
	if code == http.StatusNoContent || code == http.StatusNotFound || code == http.StatusOK && bytes.Equal(raw, []byte("null")) {
		return "idle"
	}
	if code == http.StatusConflict || code == http.StatusGone {
		return "result_lost"
	}
	if code != http.StatusOK {
		return "unavailable"
	}
	d, e := windowseventwire.DecodeDescription(raw)
	if e != nil {
		return "denied"
	}
	local := windowsEventContentContext(s.material)
	policy, e := windowseventrequest.Authorize(d, c, local, s.now().UTC())
	if e != nil {
		return "denied"
	}
	claim, e := windowseventwire.ClaimFor(d, policy)
	if e != nil {
		return "denied"
	}
	fresh, e := s.local(s.material)
	if e != nil || fresh != c {
		return "denied"
	}
	e = s.metadata(s.material, c, func(st windowseventstate.Storage) error {
		return windowseventstate.BeginClaim(st, local, d, c, policy, s.now().UTC())
	})
	if e != nil {
		if errors.Is(e, windowseventstate.ErrConsumed) {
			s.status(ctx, claim, "result_lost")
			return "result_lost"
		}
		return "state_unavailable"
	}
	body, e = windowseventwire.EncodeClaim(claim)
	if e != nil {
		return "denied"
	}
	raw, code, e = s.exchange(ctx, windowseventwire.ClaimPath, d.Identity.Sequence, body)
	if e != nil || code != http.StatusOK {
		return "result_lost"
	}
	grant, e := windowseventwire.DecodeGrant(raw)
	if e != nil || !reflect.DeepEqual(grant.Description, d) || grant.PolicyDigest != policy || grant.ClaimedAt.After(s.now().UTC()) {
		return "denied"
	}
	fresh, e = s.local(s.material)
	if e != nil || fresh != c {
		return "denied"
	}
	if _, e = windowseventrequest.Authorize(d, fresh, local, s.now().UTC()); e != nil {
		return "denied"
	}
	report, readErr := s.collect(ctx, windowseventworker.Request{Description: d, PolicyDigest: policy, Local: local, Consent: c, ClaimedAt: grant.ClaimedAt})
	if ctx.Err() != nil {
		return "reader_unavailable"
	}
	result := windowseventwire.Result{Claim: claim, Report: report}
	if windowseventwire.ValidateResultForGrant(result, grant) != nil || report.CollectedAt.After(s.now().UTC()) {
		_ = readErr
		s.status(ctx, claim, "reader_unavailable")
		return "reader_unavailable"
	}
	fresh, e = s.local(s.material)
	if e != nil || fresh != c {
		return "denied"
	}
	if _, e = windowseventrequest.Authorize(d, fresh, local, s.now().UTC()); e != nil {
		return "denied"
	}
	body, e = windowseventwire.EncodeResult(result)
	if e != nil {
		return "result_lost"
	}
	digest, e := windowseventwire.ReportDigest(report, d.Query)
	if e != nil {
		clear(body)
		return "result_lost"
	}
	s.pending = &windowsEventContentPending{memory: &journalMemory{raw: body}, done: make(chan struct{}), grant: grant, consent: c, digest: digest}
	s.pending.startExpiry()
	return s.deliver(ctx)
}
func (s *windowsEventContentSender) deliver(ctx context.Context) string {
	if status := s.prune(); status != "pending_retained" {
		return status
	}
	p := s.pending
	bounded, cancel := context.WithDeadline(ctx, p.grant.Description.ExpiresAt)
	defer cancel()
	fresh, e := s.local(s.material)
	if e != nil || fresh != p.consent {
		s.discard()
		return "denied"
	}
	digest, e := windowseventrequest.Authorize(p.grant.Description, fresh, windowsEventContentContext(s.material), s.now().UTC())
	if e != nil || digest != p.grant.PolicyDigest {
		s.discard()
		return "denied"
	}
	p.memory.mu.Lock()
	if p.memory.expired || len(p.memory.raw) == 0 {
		p.memory.mu.Unlock()
		s.discard()
		return "expired"
	}
	reply, code, e := s.exchange(bounded, windowseventwire.ResultPath, p.grant.Description.Identity.Sequence, p.memory.raw)
	p.memory.mu.Unlock()
	if e != nil {
		return "pending_retained"
	}
	if code == http.StatusUnauthorized || code == http.StatusConflict || code == http.StatusGone || code == http.StatusForbidden {
		s.discard()
		return "result_lost"
	}
	if code != http.StatusOK {
		return "pending_retained"
	}
	receipt, e := windowseventwire.DecodeReceipt(reply)
	if e != nil || receipt.Identity != p.grant.Description.Identity || receipt.PolicyDigest != p.grant.PolicyDigest || receipt.ResultDigest != p.digest || receipt.ExpiresAt != p.grant.Description.ExpiresAt || receipt.AcceptedAt.Before(p.grant.ClaimedAt) || receipt.AcceptedAt.After(s.now().UTC()) {
		return "pending_retained"
	}
	s.discard()
	return "acknowledged"
}
func (s *windowsEventContentSender) request(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
	var req *http.Request
	var e error
	if s.material.config.Profile == "http-test" {
		req, e = windowseventwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, path, s.material.certificate, sequence, s.now().UTC(), body)
	} else {
		req, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return nil, 0, ErrTransport
	}
	response, e := s.client.Do(req)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	// Terminal rejection needs no response body to safely discard content. Do
	// not turn a plaintext/error-page rejection into a retryable transport fault.
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusGone {
		return nil, response.StatusCode, nil
	}
	if len(response.Header.Values("Content-Encoding")) != 0 {
		return nil, 0, ErrTransport
	}
	if response.StatusCode != http.StatusNoContent && (len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8")) {
		return nil, 0, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, windowseventwire.MaxMetadataBytes+1))
	if e != nil || len(raw) > windowseventwire.MaxMetadataBytes || response.StatusCode == http.StatusNoContent && len(raw) != 0 {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}
func runWindowsEventContentAttempt(ctx context.Context, s *windowsEventContentSender) string {
	if s == nil {
		return ""
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return s.Run(bounded)
}
