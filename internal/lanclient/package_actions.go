package lanclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packagewire"
	"net/http"
	"time"
)

type packageHelperClient interface {
	Capabilities(context.Context) (packagehelper.Capabilities, error)
	Submit(context.Context, []byte) (packagehelper.Snapshot, error)
	Status(context.Context, string) (packagehelper.Snapshot, error)
}
type packageSender struct {
	material Material
	client   *http.Client
	helper   packageHelperClient
	local    func(Material) (packageLocal, error)
	now      func() time.Time
	current  func(Material) bool
	exchange func(context.Context, string, uint64, []byte) ([]byte, int, error)
}

func (packageSender) String() string               { return "package action sender (private material redacted)" }
func (s packageSender) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (packageSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"privateMaterialRedacted":true}`), nil
}
func openPackageSender(m Material) *packageSender {
	s := &packageSender{material: m, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), helper: packagehelper.NewClient(), local: loadPackageLocal, now: func() time.Time { return time.Now().UTC() }, current: func(m Material) bool { return m.valid() }}
	s.exchange = s.request
	return s
}
func (s *packageSender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *packageSender) recheck(l packageLocal) error {
	if !s.current(s.material) {
		return errPackageDenied
	}
	fresh, e := s.local(s.material)
	if e != nil || fresh.revision != l.revision {
		return errPackageDenied
	}
	return nil
}
func freshPackageCapability(c packagehelper.Capabilities, now time.Time) bool {
	return packagehelper.ValidateCapabilities(c) == nil && c.CapturedAt <= now.Unix() && now.Unix()-c.CapturedAt < 60
}

// Run never retains a claimed envelope. Any lost claim/submission is recovered
// only from that same root job's status; agent restart cannot relaunch it.
func (s *packageSender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "unavailable"
	}
	if !s.material.config.complete() {
		return "disabled"
	}
	local, e := s.local(s.material)
	if errors.Is(e, errPackageDisabled) {
		return "disabled"
	}
	if e != nil || !s.current(s.material) {
		return "denied"
	}
	caps, e := s.helper.Capabilities(ctx)
	eligible := e == nil && matchPackageCapabilities(caps, local, s.material) == nil && freshPackageCapability(caps, s.now())
	if eligible {
		body, e := packagewire.EncodeCapabilities(caps)
		if e != nil || s.recheck(local) != nil {
			return "denied"
		}
		raw, code, e := s.exchange(ctx, packagewire.CapabilitiesPath, 1, body)
		eligible = e == nil && code == 200 && packagewire.DecodePeek(raw) == nil && caps.Enabled
	}
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "denied"
	}
	body, _ := packagewire.EncodePeek()
	raw, code, e := s.exchange(ctx, packagewire.PeekPath, 1, body)
	if e != nil {
		return "unavailable"
	}
	if code == 404 || code == 204 {
		return "idle"
	}
	if code != 200 {
		return "unavailable"
	}
	d, e := packagewire.DecodeDelivery(raw)
	if e != nil {
		return "denied"
	}
	if s.recheck(local) != nil {
		return "denied"
	}
	if d.State == "claimed" {
		snapshot, e := s.helper.Status(ctx, d.Identity.JobID)
		if e != nil {
			return "outcome_unknown"
		}
		return s.deliver(ctx, local, d.Identity, snapshot)
	}
	if !eligible || !freshPackageCapability(caps, s.now()) {
		return "helper_unavailable"
	}
	if s.now().Unix() >= d.StartDeadline {
		return "expired"
	}
	body, e = packagewire.EncodeClaim(d.Identity)
	if e != nil || s.recheck(local) != nil {
		return "denied"
	}
	raw, code, e = s.exchange(ctx, packagewire.ClaimPath, d.Identity.Sequence, body)
	if e != nil || code != 200 {
		return "outcome_unknown"
	}
	grant, e := packagewire.DecodeGrant(raw)
	if e != nil || grant.Identity != d.Identity {
		return "denied"
	}
	p, _, e := packagepermit.Decode(ctx, grant.Envelope)
	if e != nil || p.ManagerID != caps.ManagerID || p.KeyID != caps.KeyID || p.EndpointID != caps.EndpointID || p.IncarnationDigest != caps.IncarnationDigest || p.RootPolicyDigest != caps.RootPolicyDigest || p.StartDeadline != d.StartDeadline {
		return "denied"
	}
	allowed := map[packagepermit.Selection]bool{}
	for _, x := range caps.Allowed {
		allowed[x] = true
	}
	for _, x := range p.Selection {
		if !allowed[x] {
			return "denied"
		}
	}
	fresh, e := s.helper.Capabilities(ctx)
	if e != nil || matchPackageCapabilities(fresh, local, s.material) != nil || !fresh.Enabled || !freshPackageCapability(fresh, s.now()) || s.recheck(local) != nil {
		return "denied"
	}
	if s.now().Unix() < p.NotBefore || s.now().Unix() >= p.StartDeadline {
		return "expired"
	}
	snapshot, e := s.helper.Submit(ctx, grant.Envelope)
	if e != nil {
		return "outcome_unknown"
	}
	return s.deliver(ctx, local, d.Identity, snapshot)
}
func (s *packageSender) deliver(ctx context.Context, local packageLocal, id packagewire.Identity, result packagehelper.Snapshot) string {
	if packagehelper.ValidateSnapshot(result) != nil || result.JobID != id.JobID || result.Sequence != id.Sequence {
		return "denied"
	}
	digest := result.PreparationEnvelopeDigest
	if id.Kind == packagepermit.Execute {
		digest = result.ExecutionEnvelopeDigest
	}
	if digest != id.EnvelopeDigest {
		return "denied"
	}
	if s.recheck(local) != nil || ctx.Err() != nil {
		return "outcome_unknown"
	}
	body, e := packagewire.EncodeResult(result)
	if e != nil {
		return "denied"
	}
	raw, code, e := s.exchange(ctx, packagewire.ResultPath, id.Sequence, body)
	if e != nil || code != 200 || packagewire.DecodePeek(raw) != nil {
		return "outcome_unknown"
	}
	return "reported"
}
func (s *packageSender) request(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
	if !s.current(s.material) {
		return nil, 0, errPackageDenied
	}
	var req *http.Request
	var e error
	if s.material.config.Profile == "http-test" {
		req, e = packagewire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, path, s.material.certificate, sequence, s.now(), body)
	} else if s.material.config.Profile == "tls" {
		req, e = http.NewRequestWithContext(ctx, "POST", s.material.config.ManagerOrigin+path, bytes.NewReader(body))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		return nil, 0, errPackageDenied
	}
	if e != nil {
		return nil, 0, errPackageDenied
	}
	response, e := s.client.Do(req)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode == 204 {
		if response.ContentLength > 0 {
			return nil, 0, ErrTransport
		}
		return nil, 204, nil
	}
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, 0, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, packagewire.MaxBodyBytes+1))
	if e != nil || len(raw) > packagewire.MaxBodyBytes {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}
func runPackageLoop(ctx context.Context, s *packageSender) {
	if s == nil {
		return
	}
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
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
