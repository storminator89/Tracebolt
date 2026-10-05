package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionclient"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/actionwire"
	"localrmm/internal/enrollmentcrypto"
)

type actionHelperFixture struct {
	caps                     actionhelper.Capabilities
	result                   actionhelper.Result
	calls, submits, statuses int
	capHook                  func(int)
	submitHook               func()
	submitError              error
	statusError              error
}

func (h *actionHelperFixture) Capabilities(context.Context) (actionhelper.Capabilities, error) {
	h.calls++
	if h.capHook != nil {
		h.capHook(h.calls)
	}
	return h.caps, nil
}
func (h *actionHelperFixture) Submit(_ context.Context, raw []byte) (actionhelper.Response, error) {
	h.submits++
	if h.submitHook != nil {
		h.submitHook()
	}
	if h.submitError != nil {
		return actionhelper.Response{}, h.submitError
	}
	return actionhelper.Response{Version: actionhelper.ResponseVersion, Result: &h.result}, nil
}
func (h *actionHelperFixture) Status(_ context.Context, id, digest string) (actionhelper.Response, error) {
	h.statuses++
	if h.statusError != nil {
		return actionhelper.Response{}, h.statusError
	}
	if id != h.result.JobID || digest != h.result.EnvelopeDigest {
		return actionhelper.Response{}, errors.New("fixture mismatch")
	}
	return actionhelper.Response{Version: actionhelper.ResponseVersion, Result: &h.result}, nil
}

type serviceActionFixture struct {
	s                        *actionSender
	local                    actionLocal
	helper                   *actionHelperFixture
	now                      time.Time
	delivery                 actionjob.Delivery
	grant                    actionjob.Grant
	claimed, accepted        bool
	network, claims, results int
	exchangeHook             func(string)
	claimError, resultError  error
	current                  bool
	localError               error
}

func serviceActionTestFixture(t *testing.T) *serviceActionFixture {
	t.Helper()
	f := &serviceActionFixture{now: time.Now().UTC().Truncate(time.Second), current: true}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, 32))
	d := actionpermit.Digest([]byte("reviewed fixture"))
	agent := "agent_" + strings.Repeat("2", 32)
	manager := "manager_" + strings.Repeat("1", 32)
	m := Material{loaded: true, binding: strings.Repeat("a", 64), config: Config{SchemaVersion: CompleteConfigVersion, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Profile: "tls", ManagerOrigin: "https://manager.test", AgentID: agent}, certificate: tls.Certificate{Certificate: [][]byte{[]byte("inert endpoint DER fixture")}}}
	f.local = actionLocal{revision: d, policy: ActionClientPolicy{Version: ActionClientPolicyVersion, Enabled: true, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, ManagerID: manager, EndpointID: agent, IncarnationDigest: "sha256:" + journalLeaf(m), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), RootPolicyDigest: d, TransportProfile: actionhelper.ProductionTLS, AgentUID: 1234, AgentGID: 1234}}
	caps := actionhelper.Capabilities{Version: actionhelper.CapabilitiesVersion, Enabled: true, ManagerID: manager, KeyID: f.local.policy.KeyID, EndpointID: agent, IncarnationDigest: f.local.policy.IncarnationDigest, RootPolicyDigest: d, TransportProfile: actionhelper.ProductionTLS, CapturedAt: f.now.Unix(), MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: d}}}
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: "fixture.service", UnitPolicyDigest: d}
	pd, _ := actionpermit.PlanDigest(plan)
	p := actionpermit.Permit{Version: actionpermit.Version, ManagerID: manager, KeyID: caps.KeyID, EndpointID: agent, IncarnationDigest: caps.IncarnationDigest, JobID: "action_" + strings.Repeat("3", 32), Sequence: 1, Plan: plan, PlanDigest: pd, OperatorID: "operator_" + strings.Repeat("4", 32), ApprovalDigest: d, RootPolicyDigest: d, IssuedAt: f.now.Unix(), NotBefore: f.now.Unix(), StartDeadline: f.now.Unix() + 60}
	msg, e := actionpermit.SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	env, e := actionpermit.Encode(p, ed25519.Sign(key, msg))
	if e != nil {
		t.Fatal(e)
	}
	id := actionjob.Identity{JobID: p.JobID, Sequence: 1, EnvelopeDigest: actionpermit.Digest(env)}
	f.grant = actionjob.Grant{Identity: id, Envelope: env}
	f.delivery = actionjob.Delivery{Identity: id, State: actionjob.Approved, StartDeadline: f.now.Add(time.Minute)}
	f.helper = &actionHelperFixture{caps: caps, result: actionhelper.Result{JobID: p.JobID, Sequence: 1, EnvelopeDigest: id.EnvelopeDigest, Phase: actionstate.OperationCompleted, ConsumedAt: f.now.UnixMicro(), DispatchAt: f.now.UnixMicro(), TransitionAt: f.now.UnixMicro(), Outcome: actionstate.OutcomeCompleted, ObservedState: actionstate.ObservedActive}}
	f.s = &actionSender{material: m, helper: f.helper, local: func(Material) (actionLocal, error) {
		if f.localError != nil {
			return actionLocal{}, f.localError
		}
		return f.local, nil
	}, now: func() time.Time { return f.now }, current: func(Material) bool { return f.current }}
	f.s.exchange = func(_ context.Context, path string, seq uint64, raw []byte) ([]byte, int, error) {
		f.network++
		if f.exchangeHook != nil {
			f.exchangeHook(path)
		}
		switch path {
		case actionwire.CapabilitiesPath:
			if _, e := actionwire.DecodeCapabilities(raw); e != nil || seq != 1 {
				t.Errorf("invalid capability request %v", e)
			}
			return []byte("{}"), 200, nil
		case actionwire.PeekPath:
			if actionwire.DecodePeek(raw) != nil || seq != 1 {
				t.Error("invalid peek")
			}
			if f.accepted {
				return nil, http.StatusNoContent, nil
			}
			d := f.delivery
			if f.claimed {
				d.State = actionjob.Claimed
			}
			b, e := actionwire.EncodeDelivery(d)
			return b, 200, e
		case actionwire.ClaimPath:
			f.claims++
			id, e := actionwire.DecodeClaim(raw)
			if e != nil || id != f.grant.Identity || seq != id.Sequence {
				t.Errorf("bad claim %v", e)
			}
			if f.claimed {
				return nil, http.StatusConflict, nil
			}
			f.claimed = true
			if f.claimError != nil {
				return nil, 0, f.claimError
			}
			b, e := actionwire.EncodeGrant(f.grant)
			return b, 200, e
		case actionwire.ResultPath:
			f.results++
			r, e := actionwire.DecodeResult(raw)
			if e != nil || r != f.helper.result || seq != r.Sequence {
				t.Errorf("bad result %v", e)
			}
			if f.resultError != nil {
				return nil, 0, f.resultError
			}
			f.accepted = true
			return []byte("{}"), 200, nil
		default:
			t.Fatal("unexpected path", path)
			return nil, 0, nil
		}
	}
	return f
}
func TestServiceActionsFreshClaimSubmitsExactlyOnce(t *testing.T) {
	f := serviceActionTestFixture(t)
	if got := f.s.Run(context.Background()); got != "reported" {
		t.Fatal(got)
	}
	if f.claims != 1 || f.helper.submits != 1 || f.results != 1 {
		t.Fatal(f.claims, f.helper.submits, f.results)
	}
	if got := f.s.Run(context.Background()); got != "idle" {
		t.Fatal(got)
	}
	if f.helper.submits != 1 {
		t.Fatal("replayed")
	}
}
func TestServiceActionsAbsentDisabledInvalidGrantDoesNoIO(t *testing.T) {
	for _, err := range []error{errActionDisabled, errActionDenied} {
		t.Run(err.Error(), func(t *testing.T) {
			f := serviceActionTestFixture(t)
			f.localError = err
			f.s.Run(context.Background())
			if f.network != 0 || f.helper.calls != 0 || f.helper.submits != 0 {
				t.Fatal("I/O without grant")
			}
		})
	}
}
func TestServiceActionsClaimLostNeverSubmitsOnRecovery(t *testing.T) {
	f := serviceActionTestFixture(t)
	f.claimError = ErrTransport
	f.helper.statusError = errors.New("no consumed helper record")
	if got := f.s.Run(context.Background()); got != "outcome_unknown" {
		t.Fatal(got)
	}
	f.claimError = nil
	if got := f.s.Run(context.Background()); got != "outcome_unknown" {
		t.Fatal(got)
	}
	if f.claims != 1 || f.helper.submits != 0 || f.helper.statuses != 1 {
		t.Fatal(f.claims, f.helper.submits, f.helper.statuses)
	}
}
func TestServiceActionsLostSubmitOrResultReadsSameStatus(t *testing.T) {
	for _, kind := range []string{"submit", "result"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			if kind == "submit" {
				f.helper.submitError = actionclient.ErrUncertain
			} else {
				f.resultError = ErrTransport
			}
			if got := f.s.Run(context.Background()); got != "outcome_unknown" {
				t.Fatal(got)
			}
			f.helper.submitError = nil
			f.resultError = nil
			copy := *f.s
			f.s = &copy
			if got := f.s.Run(context.Background()); got != "reported" {
				t.Fatal(got)
			}
			if f.helper.submits != 1 || f.claims != 1 || f.helper.statuses != 1 {
				t.Fatal("replayed", f.helper.submits, f.claims, f.helper.statuses)
			}
		})
	}
}
func TestServiceActionsRecheckBeforeSoleSubmit(t *testing.T) {
	for _, kind := range []string{"grant_revoked", "root_changed", "endpoint_invalid", "deadline", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.helper.capHook = func(n int) {
				if n != 2 {
					return
				}
				switch kind {
				case "grant_revoked":
					f.localError = errActionDisabled
				case "root_changed":
					f.helper.caps.RootPolicyDigest = actionpermit.Digest([]byte("changed"))
				case "endpoint_invalid":
					f.current = false
				case "deadline":
					f.now = f.now.Add(time.Minute)
				case "canceled":
					cancel()
				}
			}
			f.s.Run(ctx)
			if f.helper.submits != 0 || !f.claimed {
				t.Fatal(f.helper.submits, f.claimed)
			}
		})
	}
}
func TestServiceActionsPolicyRevocationDoesNotStrandHistoricalStatus(t *testing.T) {
	for _, kind := range []string{"disabled", "policy", "stale"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			f.claimed = true
			switch kind {
			case "disabled":
				f.helper.caps.Enabled = false
			case "policy":
				f.helper.caps.RootPolicyDigest = actionpermit.Digest([]byte("new policy"))
			case "stale":
				f.helper.caps.CapturedAt -= 60
			}
			if got := f.s.Run(context.Background()); got != "reported" {
				t.Fatal(got)
			}
			if f.helper.submits != 0 || f.claims != 0 || f.helper.statuses != 1 {
				t.Fatal("bad recovery")
			}
		})
	}
}
func TestServiceActionsIneligibleCapabilitiesNeverClaim(t *testing.T) {
	for _, kind := range []string{"disabled", "policy", "stale", "profile", "endpoint", "key"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			switch kind {
			case "disabled":
				f.helper.caps.Enabled = false
			case "policy":
				f.helper.caps.RootPolicyDigest = actionpermit.Digest(nil)
			case "stale":
				f.helper.caps.CapturedAt -= 60
			case "profile":
				f.helper.caps.TransportProfile = actionhelper.DisposableHTTPTest
				f.helper.caps.HTTPTestAcknowledged = true
			case "endpoint":
				f.helper.caps.EndpointID = "agent_" + strings.Repeat("5", 32)
			case "key":
				f.helper.caps.KeyID = actionpermit.Digest(nil)
			}
			if got := f.s.Run(context.Background()); got != "helper_unavailable" {
				t.Fatal(got)
			}
			if f.claims != 0 || f.helper.submits != 0 {
				t.Fatal("claimed")
			}
		})
	}
}
func TestServiceActionsWrongResultCannotBeReported(t *testing.T) {
	f := serviceActionTestFixture(t)
	f.helper.result.EnvelopeDigest = actionpermit.Digest(nil)
	if got := f.s.Run(context.Background()); got != "denied" {
		t.Fatal(got)
	}
	if f.results != 0 {
		t.Fatal("reported wrong job")
	}
}
func TestServiceActionsUnchangedGrantRevisionRequired(t *testing.T) {
	f := serviceActionTestFixture(t)
	f.exchangeHook = func(path string) {
		if path == actionwire.ClaimPath {
			f.local.revision = actionpermit.Digest([]byte("replaced same grant"))
		}
	}
	f.s.Run(context.Background())
	if f.helper.submits != 0 {
		t.Fatal("started after replacement")
	}
}
func TestServiceActionsExplicitHTTPGrantOnly(t *testing.T) {
	f := serviceActionTestFixture(t)
	p := f.local.policy
	m := f.s.material
	if e := validateActionLocal(p, m, 1234, 1234); e != nil {
		t.Fatal(e)
	}
	m.config.Profile = "http-test"
	m.config.ManagerOrigin = "http://manager.test"
	m.config.InsecureHTTPAcknowledged = true
	p.ManagerOrigin = m.config.ManagerOrigin
	p.TransportProfile = actionhelper.DisposableHTTPTest
	if e := validateActionLocal(p, m, 1234, 1234); e == nil {
		t.Fatal("implicit plaintext")
	}
	p.HTTPTestAcknowledged = true
	if e := validateActionLocal(p, m, 1234, 1234); e != nil {
		t.Fatal(e)
	}
}
func TestServiceActionsLoopJoinsOnCancellation(t *testing.T) {
	f := serviceActionTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.localError = errActionDisabled
	f.s.local = func(Material) (actionLocal, error) { cancel(); return actionLocal{}, errActionDisabled }
	done := make(chan struct{})
	go func() { runActionLoop(ctx, f.s); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop not joined")
	}
	if f.network != 0 || f.helper.calls != 0 {
		t.Fatal("I/O from disabled loop")
	}
}

func TestServiceActionsDiagnosticFormattingRedactsMaterial(t *testing.T) {
	f := serviceActionTestFixture(t)
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, *f.s)
		if strings.Contains(output, f.local.policy.EndpointID) || strings.Contains(output, f.local.policy.SenderBinding) || !strings.Contains(output, "redacted") {
			t.Fatal("unredacted sender")
		}
	}
	raw, e := json.Marshal(f.s)
	if e != nil || string(raw) != `{"privateMaterialRedacted":true}` {
		t.Fatal("unredacted JSON", e)
	}
}
