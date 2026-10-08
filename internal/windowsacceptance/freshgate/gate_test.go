package freshgate

import (
	"strings"
	"testing"
	"time"
)

func approvedFixture() (Approval, Runtime, time.Time) {
	n := time.Unix(1900000000, 0)
	a := Approval{Profile: Profile, Source: strings.Repeat("a", 40), TestSHA256: strings.Repeat("b", 64), ServiceSHA256: strings.Repeat("c", 64), Machine: "disposable-01", RunID: "123", Attempt: "1", ExpiresUnix: n.Add(4 * time.Minute).Unix(), Services: true, Identity: true, AppACLs: true, FiveReadScopes: true, SyntheticConsole: true, LoopbackTLS: true, RetainForVMDisposal: true, StopOwnedService: true}
	r := Runtime{Source: a.Source, CompiledSource: a.Source, TestSHA256: a.TestSHA256, ServiceSHA256: a.ServiceSHA256, Machine: a.Machine, RunID: a.RunID, Attempt: a.Attempt, Repository: Repository, Event: "workflow_dispatch", Actions: "true", RunnerEnvironment: "github-hosted", RunnerOS: "Windows", RepositoryOwner: Owner, RepositoryOwnerID: OwnerID, Actor: Owner, ActorID: OwnerID, TriggeringActor: Owner}
	return a, r, n
}
func TestFreshGateExactBindings(t *testing.T) {
	a, r, n := approvedFixture()
	g, e := Authorize(a, r, func() time.Time { return n })
	if e != nil || !g.Check() {
		t.Fatal("valid refused")
	}
	g.Close()
	if g.Check() {
		t.Fatal("closed grant")
	}
	for name, edit := range map[string]func(*Runtime){"source": func(r *Runtime) { r.Source = "" }, "compiled": func(r *Runtime) { r.CompiledSource = "" }, "test": func(r *Runtime) { r.TestSHA256 = "" }, "service": func(r *Runtime) { r.ServiceSHA256 = "" }, "machine": func(r *Runtime) { r.Machine = "other" }, "run": func(r *Runtime) { r.RunID = "124" }, "attempt": func(r *Runtime) { r.Attempt = "2" }, "event": func(r *Runtime) { r.Event = "push" }, "runner": func(r *Runtime) { r.RunnerEnvironment = "self-hosted" }} {
		t.Run(name, func(t *testing.T) {
			x := r
			edit(&x)
			if _, e := Authorize(a, x, func() time.Time { return n }); e == nil {
				t.Fatal("binding admitted")
			}
		})
	}
}
func TestFreshGateNoImplicitConsent(t *testing.T) {
	a, r, n := approvedFixture()
	for _, edit := range []func(*Approval){func(a *Approval) { a.Services = false }, func(a *Approval) { a.Identity = false }, func(a *Approval) { a.AppACLs = false }, func(a *Approval) { a.FiveReadScopes = false }, func(a *Approval) { a.SyntheticConsole = false }, func(a *Approval) { a.LoopbackTLS = false }, func(a *Approval) { a.RetainForVMDisposal = false }, func(a *Approval) { a.StopOwnedService = false }, func(a *Approval) { a.Profile = "windows-inventory-v1" }, func(a *Approval) { a.ExpiresUnix = n.Unix() }, func(a *Approval) { a.ExpiresUnix = n.Add(MaxLifetime + time.Second).Unix() }} {
		x := a
		edit(&x)
		if _, e := Authorize(x, r, func() time.Time { return n }); e == nil {
			t.Fatal("missing/distinct approval admitted")
		}
	}
}
func TestFreshGateExpiryNotRenewed(t *testing.T) {
	a, r, n := approvedFixture()
	g, e := Authorize(a, r, func() time.Time { return n })
	if e != nil {
		t.Fatal(e)
	}
	n = n.Add(4 * time.Minute)
	if g.Check() {
		t.Fatal("expired authority")
	}
}

func TestFreshGateRejectsRerunEvenWithMatchingBindings(t *testing.T) {
	a, r, n := approvedFixture()
	a.Attempt = "2"
	r.Attempt = "2"
	if _, e := Authorize(a, r, func() time.Time { return n }); e == nil {
		t.Fatal("old dispatch approval replayed on rerun")
	}
}

func TestFreshGateRequiresVerifiedOwnerActors(t *testing.T) {
	a, r, n := approvedFixture()
	for name, edit := range map[string]func(*Runtime){
		"owner missing":        func(r *Runtime) { r.RepositoryOwner = "" },
		"owner wrong":          func(r *Runtime) { r.RepositoryOwner = "collaborator" },
		"owner ID missing":     func(r *Runtime) { r.RepositoryOwnerID = "" },
		"owner ID wrong":       func(r *Runtime) { r.RepositoryOwnerID = "123" },
		"actor missing":        func(r *Runtime) { r.Actor = "" },
		"actor collaborator":   func(r *Runtime) { r.Actor = "collaborator" },
		"actor ID missing":     func(r *Runtime) { r.ActorID = "" },
		"actor ID wrong":       func(r *Runtime) { r.ActorID = "123" },
		"trigger missing":      func(r *Runtime) { r.TriggeringActor = "" },
		"trigger collaborator": func(r *Runtime) { r.TriggeringActor = "collaborator" },
	} {
		t.Run(name, func(t *testing.T) {
			x := r
			edit(&x)
			if _, e := Authorize(a, x, func() time.Time { return n }); e == nil {
				t.Fatal("non-owner or missing actor facts admitted")
			}
		})
	}
}
