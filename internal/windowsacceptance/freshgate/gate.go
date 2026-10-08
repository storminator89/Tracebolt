// Package freshgate defines a separate manual-only source/artifact/machine gate.
// All functions here are inert. It grants no authority by import or test execution.
package freshgate

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"localrmm/internal/windowsacceptance/profile"
)

const Profile = "fresh-read-conpty-v1"
const Repository = "storminator89/Tracebolt"
const Owner = "storminator89"
const OwnerID = "30489872"
const MaxLifetime = 15 * time.Minute

var ErrGuard = errors.New("fresh native acceptance authorization unavailable")

type Approval struct {
	Profile, Source, TestSHA256, ServiceSHA256, Machine, RunID, Attempt                                               string
	ExpiresUnix                                                                                                       int64
	Services, Identity, AppACLs, FiveReadScopes, SyntheticConsole, LoopbackTLS, RetainForVMDisposal, StopOwnedService bool
}
type Runtime struct{ Source, CompiledSource, TestSHA256, ServiceSHA256, Machine, RunID, Attempt, Repository, Event, Actions, RunnerEnvironment, RunnerOS, RepositoryOwner, RepositoryOwnerID, Actor, ActorID, TriggeringActor string }
type Grant struct {
	approval Approval
	now      func() time.Time
	live     atomic.Bool
}

func validHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && strings.ToLower(s) == s
}
func safeID(s string) bool {
	if len(s) < 1 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func decimal(s string) bool {
	if len(s) == 0 || len(s) > 24 || s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func Authorize(a Approval, r Runtime, now func() time.Time) (*Grant, error) {
	if now == nil || a.Profile != Profile || !validHex(a.Source, 20) || !validHex(a.TestSHA256, 32) || !validHex(a.ServiceSHA256, 32) || a.TestSHA256 == a.ServiceSHA256 || !safeID(a.Machine) || !decimal(a.RunID) || a.Attempt != "1" || !a.Services || !a.Identity || !a.AppACLs || !a.FiveReadScopes || !a.SyntheticConsole || !a.LoopbackTLS || !a.RetainForVMDisposal || !a.StopOwnedService {
		return nil, ErrGuard
	}
	if r.Source != a.Source || r.CompiledSource != a.Source || r.TestSHA256 != a.TestSHA256 || r.ServiceSHA256 != a.ServiceSHA256 || r.Machine != a.Machine || r.RunID != a.RunID || r.Attempt != a.Attempt || r.Repository != Repository || r.Event != "workflow_dispatch" || r.Actions != "true" || r.RunnerEnvironment != "github-hosted" || r.RunnerOS != "Windows" {
		return nil, ErrGuard
	}
	// GitHub write access is not owner approval. Missing actor facts fail closed.
	if r.RepositoryOwner != Owner || r.RepositoryOwnerID != OwnerID || r.Actor != Owner || r.ActorID != OwnerID || r.TriggeringActor != Owner {
		return nil, ErrGuard
	}
	expires := time.Unix(a.ExpiresUnix, 0)
	t := now()
	if !t.Before(expires) || expires.Sub(t) > MaxLifetime || expires.Sub(t) < 3*time.Minute {
		return nil, ErrGuard
	}
	g := &Grant{approval: a, now: now}
	g.live.Store(true)
	return g, nil
}
func (g *Grant) Check() bool {
	return g != nil && g.now != nil && g.live.Load() && g.now().Before(time.Unix(g.approval.ExpiresUnix, 0))
}
func (g *Grant) Close() {
	if g != nil {
		g.live.Store(false)
	}
}
func (g *Grant) Deadline() time.Time {
	if g == nil {
		return time.Time{}
	}
	return time.Unix(g.approval.ExpiresUnix, 0)
}
func (g *Grant) Selection() profile.Selection {
	return profile.Selection{CollectionProfile: "windows-inventory-v1", Transport: "tls"}
}
func (g *Grant) ExtensionsApproved() bool { return g != nil && g.Check() }
