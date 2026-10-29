package windowscustomerflow

import (
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsfullsoftware"
)

func fixture(t *testing.T) (State, Evidence, time.Time) {
	t.Helper()
	now := time.Unix(1900000000, 0).UTC()
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), ClaimID: "claim_" + strings.Repeat("4", 32), ClaimHash: strings.Repeat("a", 64), KeyFingerprint: strings.Repeat("b", 64), IssuerFingerprint: strings.Repeat("c", 64), ProfileDigest: strings.Repeat("d", 64), ExecutableDigest: strings.Repeat("e", 64), ServiceDigest: strings.Repeat("f", 64), DeadlineAt: now.Unix() + 600}
	c := Consent{Scopes: lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV14, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: lanclient.WindowsReadAdminScopesV14(), Acknowledged: true}, AutomaticFinalizerAcknowledged: true}
	s, err := New(b, c, now)
	if err != nil {
		t.Fatal(err)
	}
	e := Evidence{Binding: b, Consent: c, ApprovalDigest: strings.Repeat("a", 64), IdentityDigest: strings.Repeat("b", 64), OriginalReceiptValid: true, OwnedServiceValid: true, IssuerCurrent: true, ApprovalCurrent: true, StoppedAndDisabled: true, ActivatedIdentity: true, ServiceRunning: true, StartupAutomaticVerified: true}
	for _, scope := range c.Scopes.Scopes[1:] {
		e.GrantDigests = append(e.GrantDigests, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("c", 64)})
	}
	return s, e, now
}

func step(t *testing.T, s State, a Action, e Evidence, at time.Time) State {
	t.Helper()
	next, err := Advance(s, a, e, at)
	if err != nil {
		t.Fatalf("%s rejected: %v", a, err)
	}
	return next
}

func TestFreshContinuationRequiresExactConsent(t *testing.T) {
	s, e, now := fixture(t)
	for name, mutate := range map[string]func(*Consent){"no finalizer consent": func(c *Consent) { c.AutomaticFinalizerAcknowledged = false }, "no local scope consent": func(c *Consent) { c.Scopes.Acknowledged = false }, "scope removed": func(c *Consent) { c.Scopes.Scopes = c.Scopes.Scopes[:len(c.Scopes.Scopes)-1] }, "old scope version": func(c *Consent) { c.Scopes.SchemaVersion = lanclient.WindowsCapabilityConsentVersionV13 }, "http acknowledgement": func(c *Consent) { c.Scopes.InsecureHTTPAcknowledged = true }} {
		t.Run(name, func(t *testing.T) {
			c := e.Consent
			c.Scopes.Scopes = append([]string(nil), c.Scopes.Scopes...)
			mutate(&c)
			if _, err := New(s.Binding, c, now); err == nil {
				t.Fatal("unapproved consent accepted")
			}
		})
	}
	e.Consent.Scopes.Scopes[0] = "changed"
	if s.Consent.Scopes.Scopes[0] == "changed" {
		t.Fatal("state aliases consent input")
	}
}

func TestContinuationRequiresOriginalBindingAndAllGrants(t *testing.T) {
	s, e, now := fixture(t)
	for name, mutate := range map[string]func(*Evidence){"changed customer": func(x *Evidence) { x.Binding.CustomerID = "customer_" + strings.Repeat("9", 32) }, "changed claim": func(x *Evidence) { x.Binding.ClaimHash = strings.Repeat("9", 64) }, "changed consent": func(x *Evidence) { x.Consent.AutomaticFinalizerAcknowledged = false }, "no receipt": func(x *Evidence) { x.OriginalReceiptValid = false }, "wrong service": func(x *Evidence) { x.OwnedServiceValid = false }, "no issuer": func(x *Evidence) { x.IssuerCurrent = false }, "no approval": func(x *Evidence) { x.ApprovalCurrent = false }, "service enabled": func(x *Evidence) { x.StoppedAndDisabled = false }, "no approval digest": func(x *Evidence) { x.ApprovalDigest = "" }} {
		t.Run(name, func(t *testing.T) {
			v := e
			mutate(&v)
			if _, err := Advance(s, BeginActivation, v, now); err == nil {
				t.Fatal("unsafe activation accepted")
			}
		})
	}
	s = step(t, s, BeginActivation, e, now)
	if _, err := Advance(s, BeginActivation, e, now); err == nil {
		t.Fatal("native activation retried")
	}
	bad := e
	bad.ActivatedIdentity = false
	if _, err := Advance(s, FinishActivation, bad, now); err == nil {
		t.Fatal("missing activated identity accepted")
	}
	s = step(t, s, FinishActivation, e, now)
	s = step(t, s, BeginGrants, e, now)
	bad = e
	bad.GrantDigests = bad.GrantDigests[:len(bad.GrantDigests)-1]
	if _, err := Advance(s, FinishGrants, bad, now); err == nil {
		t.Fatal("partial grants accepted")
	}
	bad = e
	bad.GrantDigests = append([]lanclient.WindowsCapabilityGrantDigest(nil), e.GrantDigests...)
	bad.GrantDigests[0].SHA256 = ""
	if _, err := Advance(s, FinishGrants, bad, now); err == nil {
		t.Fatal("invalid grant accepted")
	}
	bad = e
	bad.GrantDigests = append([]lanclient.WindowsCapabilityGrantDigest(nil), e.GrantDigests...)
	foundHistory := false
	for i := range bad.GrantDigests {
		if bad.GrantDigests[i].Scope == windowsfullsoftware.HistoryScope {
			bad.GrantDigests[i].SHA256 = strings.Repeat("d", 64)
			foundHistory = true
		}
	}
	if !foundHistory {
		t.Fatal("history fixture missing")
	}
	if _, err := Advance(s, FinishGrants, bad, now); err == nil {
		t.Fatal("history and software grants not bound")
	}
	s = step(t, s, FinishGrants, e, now)
	e.GrantDigests[0].SHA256 = strings.Repeat("d", 64)
	if _, err := Advance(s, BeginStartup, e, now); err == nil {
		t.Fatal("replaced grant accepted")
	}
	e.GrantDigests[0].SHA256 = strings.Repeat("c", 64)
	s = step(t, s, BeginStartup, e, now)
	bad = e
	bad.ServiceRunning = false
	if _, err := Advance(s, FinishStartup, bad, now); err == nil {
		t.Fatal("unproved service state accepted")
	}
	bad = e
	bad.StartupAutomaticVerified = false
	if _, err := Advance(s, FinishStartup, bad, now); err == nil {
		t.Fatal("unproved startup mode accepted")
	}
	s = step(t, s, FinishStartup, e, now)
	if s.Phase != Completed {
		t.Fatal("completion missing")
	}
}

func TestInterruptedNativeOperationsNeverRearm(t *testing.T) {
	base, e, now := fixture(t)
	activation := step(t, base, BeginActivation, e, now)
	identity := step(t, activation, FinishActivation, e, now)
	grant := step(t, identity, BeginGrants, e, now)
	verified := step(t, grant, FinishGrants, e, now)
	startup := step(t, verified, BeginStartup, e, now)
	for _, s := range []State{activation, grant, startup} {
		v := e
		v.ApprovalCurrent = false
		v.IssuerCurrent = false
		v.OwnedServiceValid = false
		stopped := step(t, s, Interrupt, v, time.Unix(s.Binding.DeadlineAt+1, 0))
		if stopped.Phase != Indeterminate {
			t.Fatal("uncertain state missing")
		}
		for _, action := range []Action{BeginActivation, FinishActivation, BeginGrants, FinishGrants, BeginStartup, FinishStartup} {
			if _, err := Advance(stopped, action, e, time.Unix(s.Binding.DeadlineAt+1, 0)); err == nil {
				t.Fatal("uncertain operation resumed")
			}
		}
	}
	if _, err := Advance(base, BeginActivation, e, time.Unix(base.Binding.DeadlineAt, 0)); err == nil {
		t.Fatal("expired approval accepted")
	}
	if _, err := Advance(base, BeginActivation, e, now.Add(-time.Second)); err == nil {
		t.Fatal("clock regression accepted")
	}
}
