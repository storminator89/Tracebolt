package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionwire"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

type WindowsActionRelayGrant struct {
	Version          string                `json:"version"`
	Enabled          bool                  `json:"enabled"`
	SenderBinding    string                `json:"senderBinding"`
	ManagerOrigin    string                `json:"managerOrigin"`
	Binding          windowsaction.Binding `json:"binding"`
	HTTPAcknowledged bool                  `json:"httpAcknowledged"`
}

func windowsActionRelayOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"grant.json"}, LockName: "relay.lock", TempName: "relay.tmp", MaxBytes: 4096, Create: create}
}
func windowsActionRelayPath(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-action-relay"
}
func validateWindowsActionGrant(m Material, g WindowsActionRelayGrant) error {
	if !m.config.windowsInventory() || g.Version != "tracebolt.windows-service-action-relay.v1" || !windowsaction.ValidBinding(g.Binding) || g.SenderBinding != m.binding || g.ManagerOrigin != m.config.ManagerOrigin || g.Binding.EndpointID != m.config.AgentID || g.Binding.IncarnationDigest != "sha256:"+journalLeaf(m) || g.HTTPAcknowledged != (m.config.Profile == "http-test") {
		return ErrConfiguration
	}
	return nil
}

// InitializeWindowsActionRelayCreateOnly is the separate local setup seam. It
// cannot install the broker or grant SCM rights and is never called by an old
// read grant or by the manager. The stopped-owned-service coordinator must
// already hold its installer lease. The broker's independent used fence is the
// action authority; recreating a relay cannot reset a job or sequence.
func ValidateWindowsActionRelaySetup(path string, b windowsaction.Binding, httpAcknowledged bool) error {
	if ValidateGuidedHandoff(path) != nil {
		return ErrState
	}
	m, e := Load(path)
	if e != nil || validateUpdatesActivatedMaterial(path, m) != nil {
		return ErrState
	}
	return validateWindowsActionGrant(m, WindowsActionRelayGrant{"tracebolt.windows-service-action-relay.v1", true, m.binding, m.config.ManagerOrigin, b, httpAcknowledged})
}

func InitializeWindowsActionRelayCreateOnly(path string, b windowsaction.Binding, httpAcknowledged bool) error {
	if ValidateGuidedHandoff(path) != nil {
		return ErrState
	}
	m, e := Load(path)
	if e != nil || validateUpdatesActivatedMaterial(path, m) != nil {
		return ErrState
	}
	g := WindowsActionRelayGrant{"tracebolt.windows-service-action-relay.v1", true, m.binding, m.config.ManagerOrigin, b, httpAcknowledged}
	if validateWindowsActionGrant(m, g) != nil {
		return ErrConfiguration
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(windowsActionRelayPath(m), windowsActionRelayOptions(sid, true))
	if e != nil {
		return ErrState
	}
	defer s.Close()
	raw, _ := json.Marshal(g)
	if s.Write("grant.json", raw) != nil || s.Close() != nil {
		return ErrState
	}
	return nil
}
func readWindowsActionRelay(m Material) (WindowsActionRelayGrant, error) {
	if !m.config.windowsInventory() {
		return WindowsActionRelayGrant{}, ErrConfiguration
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return WindowsActionRelayGrant{}, e
	}
	s, e := windowsstate.Open(windowsActionRelayPath(m), windowsActionRelayOptions(sid, false))
	if e != nil {
		return WindowsActionRelayGrant{}, e
	}
	defer s.Close()
	raw, e := s.Read("grant.json")
	var g WindowsActionRelayGrant
	if e != nil || windowsaction.DecodeCanonical(raw, &g, 4096) != nil || validateWindowsActionGrant(m, g) != nil || s.Close() != nil {
		return g, ErrState
	}
	return g, nil
}

type windowsActionBroker interface {
	Capabilities(context.Context) (windowsaction.Capabilities, error)
	Submit(context.Context, []byte) (windowsaction.Result, error)
	Status(context.Context, windowsaction.Identity) (windowsaction.Result, error)
}
type windowsActionSender struct {
	material Material
	client   *http.Client
	broker   windowsActionBroker
	local    func(Material) (WindowsActionRelayGrant, error)
	current  func(Material) bool
	now      func() time.Time
	exchange func(context.Context, string, uint64, []byte) ([]byte, int, error)
}

func openWindowsActionSender(m Material) *windowsActionSender {
	if !m.config.windowsInventory() {
		return nil
	}
	s := &windowsActionSender{material: m, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), broker: windowsaction.Client{}, local: readWindowsActionRelay, current: func(m Material) bool { return currentWindowsContextMaterial(m, Load) }, now: func() time.Time { return time.Now().UTC() }}
	s.exchange = s.request
	return s
}
func (s *windowsActionSender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *windowsActionSender) recheck(g WindowsActionRelayGrant) bool {
	if !s.current(s.material) {
		return false
	}
	fresh, e := s.local(s.material)
	return e == nil && fresh == g && fresh.Enabled
}
func (s *windowsActionSender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "disabled"
	}
	g, e := s.local(s.material)
	if errors.Is(e, os.ErrNotExist) || e == nil && !g.Enabled {
		return "disabled"
	}
	if e != nil || !s.recheck(g) {
		return "denied"
	}
	caps, e := s.broker.Capabilities(ctx)
	eligible := e == nil && caps.Binding == g.Binding && windowsactionwire.CheckCapabilityTime(caps, s.now()) == nil && caps.Enabled && !caps.Busy
	if e == nil && caps.Binding == g.Binding && windowsactionwire.CheckCapabilityTime(caps, s.now()) == nil {
		body, _ := windowsactionwire.EncodeCapabilities(caps)
		if !s.recheck(g) {
			return "denied"
		}
		raw, code, e := s.exchange(ctx, windowsactionwire.CapabilitiesPath, 1, body)
		eligible = eligible && e == nil && code == http.StatusOK && windowsactionwire.DecodePeek(raw) == nil
	}
	if !s.recheck(g) || ctx.Err() != nil {
		return "denied"
	}
	body, _ := windowsactionwire.EncodePeek()
	raw, code, e := s.exchange(ctx, windowsactionwire.PeekPath, 1, body)
	if e != nil {
		return "unavailable"
	}
	if code == http.StatusNoContent || code == http.StatusNotFound {
		return "idle"
	}
	if code != http.StatusOK {
		return "unavailable"
	}
	d, e := windowsactionwire.DecodeDelivery(raw)
	if e != nil {
		return "denied"
	}
	if d.State == "claimed" || d.State == "needs_intervention" {
		result, e := s.broker.Status(ctx, d.Identity)
		if e != nil {
			return "outcome_unknown"
		}
		return s.deliver(ctx, g, d.Identity, result)
	}
	if !eligible || d.State != "approved" || !s.now().Before(d.StartDeadline) || !s.recheck(g) {
		return "denied"
	}
	body, _ = windowsactionwire.EncodeClaim(d.Identity)
	raw, code, e = s.exchange(ctx, windowsactionwire.ClaimPath, d.Identity.Sequence, body)
	if e != nil || code != http.StatusOK {
		return "outcome_unknown"
	}
	grant, e := windowsactionwire.DecodeGrant(raw)
	if e != nil || grant.Identity != d.Identity {
		return "denied"
	}
	p, e := windowsaction.Decode(grant.Envelope)
	if e != nil || p.Binding != g.Binding || p.Deadline != d.StartDeadline.Unix() || s.now().Unix() < p.NotBefore || s.now().Unix() >= p.Deadline {
		return "denied"
	}
	fresh, e := s.broker.Capabilities(ctx)
	if e != nil || fresh.Binding != g.Binding || !fresh.Enabled || fresh.Busy || windowsactionwire.CheckCapabilityTime(fresh, s.now()) != nil || !s.recheck(g) || ctx.Err() != nil {
		return "denied"
	}
	// Forward the original signed bytes once. A lost response remains claimed,
	// so every later attempt is status-only, including after agent restart.
	result, e := s.broker.Submit(ctx, grant.Envelope)
	if windowsaction.ValidateResult(result) != nil {
		return "outcome_unknown"
	}
	if e != nil && result.Phase != "complete" {
		return "outcome_unknown"
	}
	return s.deliver(ctx, g, d.Identity, result)
}
func (s *windowsActionSender) deliver(ctx context.Context, g WindowsActionRelayGrant, id windowsaction.Identity, r windowsaction.Result) string {
	if windowsaction.ValidateResult(r) != nil || r.Identity != id || r.Target != g.Binding.Target || !s.recheck(g) || ctx.Err() != nil {
		return "outcome_unknown"
	}
	body, _ := windowsactionwire.EncodeResult(r)
	raw, code, e := s.exchange(ctx, windowsactionwire.ResultPath, id.Sequence, body)
	if e != nil || code != http.StatusOK || windowsactionwire.DecodePeek(raw) != nil {
		return "outcome_unknown"
	}
	return "reported"
}
func (s *windowsActionSender) request(ctx context.Context, path string, seq uint64, body []byte) ([]byte, int, error) {
	if !s.current(s.material) {
		return nil, 0, ErrState
	}
	var req *http.Request
	var e error
	if s.material.config.Profile == "http-test" {
		req, e = windowsactionwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, path, s.material.certificate, seq, s.now(), body)
	} else if s.material.config.Profile == "tls" {
		req, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		return nil, 0, ErrConfiguration
	}
	if e != nil {
		return nil, 0, e
	}
	response, e := s.client.Do(req)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent && response.ContentLength <= 0 {
		return nil, response.StatusCode, nil
	}
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, 0, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, windowsactionwire.MaxBodyBytes+1))
	if e != nil || len(raw) > windowsactionwire.MaxBodyBytes {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}
func runWindowsActionLoop(ctx context.Context, s *windowsActionSender) {
	if s == nil {
		return
	}
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 55*time.Second)
		s.Run(attempt)
		cancel()
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
