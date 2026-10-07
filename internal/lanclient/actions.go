package lanclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"localrmm/internal/actionclient"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionwire"
)

const actionPollInterval = 15 * time.Second
const actionAttemptTimeout = 45 * time.Second

type actionHelperClient interface {
	Capabilities(context.Context) (actionhelper.Capabilities, error)
	Submit(context.Context, []byte) (actionhelper.Response, error)
	Status(context.Context, string, string) (actionhelper.Response, error)
}
type actionSender struct {
	material Material
	client   *http.Client
	helper   actionHelperClient
	local    func(Material) (actionLocal, error)
	now      func() time.Time
	current  func(Material) bool
	exchange func(context.Context, string, uint64, []byte) ([]byte, int, error)
}

// Diagnostic formatting must not traverse loaded endpoint credentials or
// approved action metadata held by transport dependencies.
func (actionSender) String() string               { return "service action sender (private material redacted)" }
func (s actionSender) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (actionSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"privateMaterialRedacted":true}`), nil
}

func openActionSender(m Material) *actionSender {
	s := &actionSender{material: m, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), helper: actionclient.Client{}, local: loadActionLocal, now: func() time.Time { return time.Now().UTC() }, current: func(m Material) bool { return m.valid() }}
	s.exchange = s.request
	return s
}
func (s *actionSender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *actionSender) recheck(initial actionLocal) error {
	if !s.current(s.material) {
		return errActionDenied
	}
	fresh, e := s.local(s.material)
	if e != nil || fresh.revision != initial.revision {
		return errActionDenied
	}
	return nil
}

// Run performs one serialized attempt. It never retains an envelope for retry.
// A lost claim/submission/result is recovered by reading the root helper's same
// job status, never by resubmitting manager-claimed work.
func (s *actionSender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "unavailable"
	}
	if !s.material.config.complete() {
		return "disabled"
	}
	local, e := s.local(s.material)
	if errors.Is(e, errActionDisabled) {
		return "disabled"
	}
	if e != nil || !s.current(s.material) {
		return "denied"
	}
	capabilities := func() (actionhelper.Capabilities, error) {
		if local.policy.Version == ActionClientPolicyVersionV2 {
			helper, ok := s.helper.(interface {
				FullAdminCapabilities(context.Context) (actionhelper.Capabilities, error)
			})
			if !ok {
				return actionhelper.Capabilities{}, errActionDenied
			}
			return helper.FullAdminCapabilities(ctx)
		}
		return s.helper.Capabilities(ctx)
	}
	caps, capabilityErr := capabilities()
	eligible := capabilityErr == nil && matchActionCapabilities(caps, local, s.material) == nil && actionwire.CheckCapabilityTime(caps, s.now()) == nil
	if eligible {
		body, err := actionwire.EncodeCapabilities(caps)
		path := actionwire.CapabilitiesPath
		if caps.Version == actionhelper.CapabilitiesVersionV2 {
			body, err = actionwire.EncodeCapabilitiesV2(caps)
			path = actionwire.CapabilitiesPathV2
		}
		if err != nil {
			return "denied"
		}
		if s.recheck(local) != nil || ctx.Err() != nil {
			return "denied"
		}
		reply, code, err := s.exchange(ctx, path, 1, body)
		eligible = err == nil && code == http.StatusOK && actionwire.DecodePeek(reply) == nil && caps.Enabled
	}
	// A current client grant permits bounded historical-status recovery even if
	// today's helper action policy was revoked, changed or cannot be projected.
	// Current capabilities gate NEW claims only, never reissue claimed work.
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "denied"
	}
	body, _ := actionwire.EncodePeek()
	raw, code, e := s.exchange(ctx, actionwire.PeekPath, 1, body)
	if e != nil {
		return "unavailable"
	}
	if code == http.StatusNoContent || code == http.StatusNotFound {
		return "idle"
	}
	if code != http.StatusOK {
		return "unavailable"
	}
	delivery, e := actionwire.DecodeDelivery(raw)
	if e != nil {
		return "denied"
	}
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "denied"
	}
	if delivery.State == actionjob.Claimed {
		// No envelope exists on this route. Process restart, failed/ambiguous claim
		// and lost submit response can never turn a claimed job into another start.
		response, e := s.helper.Status(ctx, delivery.Identity.JobID, delivery.Identity.EnvelopeDigest)
		if e != nil || response.Result == nil {
			return "outcome_unknown"
		}
		return s.deliver(ctx, local, delivery.Identity, *response.Result)
	}
	if !eligible || actionwire.CheckCapabilityTime(caps, s.now()) != nil {
		return "helper_unavailable"
	}
	if !s.now().Before(delivery.StartDeadline) {
		return "expired"
	}
	body, e = actionwire.EncodeClaim(delivery.Identity)
	if e != nil {
		return "denied"
	}
	raw, code, e = s.exchange(ctx, actionwire.ClaimPath, delivery.Identity.Sequence, body)
	// Never retry this claim or submit after an ambiguous response. The next
	// authenticated peek can only offer status recovery for claimed work.
	if e != nil || code != http.StatusOK {
		return "outcome_unknown"
	}
	grant, e := actionwire.DecodeGrant(raw)
	if e != nil || grant.Identity != delivery.Identity {
		return "denied"
	}
	p, e := actionpermit.Decode(grant.Envelope)
	if e != nil || p.ManagerID != caps.ManagerID || p.KeyID != caps.KeyID || p.EndpointID != caps.EndpointID || p.IncarnationDigest != caps.IncarnationDigest || p.RootPolicyDigest != caps.RootPolicyDigest || p.StartDeadline != delivery.StartDeadline.Unix() || p.StartDeadline-p.IssuedAt > caps.MaxLifetimeSeconds {
		return "denied"
	}
	allowed := false
	for _, rule := range caps.Services {
		if p.Plan.Unit == rule.Unit && p.Plan.UnitPolicyDigest == rule.UnitPolicyDigest {
			allowed = true
		}
	}
	if !allowed {
		return "denied"
	}
	// Re-read current kernel-authenticated helper authority after the manager
	// claim, then check the local grant and enrollment immediately before Submit.
	fresh, e := capabilities()
	if e != nil || matchActionCapabilities(fresh, local, s.material) != nil || !fresh.Enabled || actionwire.CheckCapabilityTime(fresh, s.now()) != nil {
		return "denied"
	}
	if caps.Version == actionhelper.CapabilitiesVersionV2 {
		matched := false
		for _, service := range fresh.Services {
			if service.Unit == p.Plan.Unit && service.UnitPolicyDigest == p.Plan.UnitPolicyDigest {
				matched = true
			}
		}
		if !matched || p.Version != actionpermit.VersionV2 {
			return "denied"
		}
	}
	now := s.now()
	if now.Unix() < p.NotBefore || now.Unix() >= p.StartDeadline {
		return "expired"
	}
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "denied"
	}
	response, e := s.helper.Submit(ctx, grant.Envelope)
	if e != nil || response.Result == nil {
		return "outcome_unknown"
	}
	return s.deliver(ctx, local, grant.Identity, *response.Result)
}
func (s *actionSender) deliver(ctx context.Context, local actionLocal, id actionjob.Identity, result actionhelper.Result) string {
	if actionhelper.ValidateResult(result) != nil || result.JobID != id.JobID || result.Sequence != id.Sequence || result.EnvelopeDigest != id.EnvelopeDigest {
		return "denied"
	}
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "outcome_unknown"
	}
	body, e := actionwire.EncodeResult(result)
	if e != nil {
		return "denied"
	}
	raw, code, e := s.exchange(ctx, actionwire.ResultPath, id.Sequence, body)
	if e != nil || code != http.StatusOK || actionwire.DecodePeek(raw) != nil {
		return "outcome_unknown"
	}
	return "reported"
}
func (s *actionSender) request(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
	if !s.current(s.material) {
		return nil, 0, errActionDenied
	}
	var req *http.Request
	var e error
	if s.material.config.Profile == "http-test" {
		req, e = actionwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, path, s.material.certificate, sequence, s.now(), body)
	} else if s.material.config.Profile == "tls" {
		req, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		return nil, 0, errActionDenied
	}
	if e != nil {
		return nil, 0, errActionDenied
	}
	response, e := s.client.Do(req)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		if response.ContentLength > 0 {
			return nil, 0, ErrTransport
		}
		return nil, response.StatusCode, nil
	}
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, 0, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, actionwire.MaxBodyBytes+1))
	if e != nil || len(raw) > actionwire.MaxBodyBytes {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}

// One separately granted loop lives outside the read-only agentloop Attempt
// callback. It is joined before foreground shutdown and cannot accumulate work.
func runActionLoop(ctx context.Context, s *actionSender) {
	if s == nil {
		return
	}
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, actionAttemptTimeout)
		s.Run(attempt)
		cancel()
		timer := time.NewTimer(actionPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
