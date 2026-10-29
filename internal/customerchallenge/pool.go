// Package customerchallenge supplies an isolated, bounded in-memory challenge
// pool. It neither accepts a claim nor grants enrollment. A restarted manager
// loses all challenges; clients need a fresh challenge for the same claim.
package customerchallenge

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/enrollmentcrypto"
)

const (
	MaxOutstanding       = 256
	MaxPeers             = 256
	MaxCustomers         = 25
	PerPeerPerMinute     = 30
	PerCustomerPerMinute = 30
	GlobalPerMinute      = 120
)

var (
	ErrInvalid     = errors.New("invalid challenge request")
	ErrBusy        = errors.New("challenge limit reached")
	ErrClock       = errors.New("challenge clock unavailable")
	ErrUnavailable = errors.New("challenge unavailable")
)

// Binding is fixed when a manager starts. It must come from the manager's
// independently configured TLS and issuer identity, not a client request.
type Binding struct {
	ManagerID, Origin, AgentOrigin, IssuerFingerprint string
}

type window struct {
	start time.Time
	count int
}

type entry struct {
	context  customerclaim.Context
	purpose  purpose
	consumed bool
}

type purpose uint8

const (
	claimPurpose purpose = iota + 1
	statusPurpose
	credentialV3Purpose
	activationV3Purpose
)

type Pool struct {
	mu        sync.Mutex
	binding   Binding
	now       func() time.Time
	random    io.Reader
	last      time.Time
	global    window
	peers     map[netip.Addr]window
	customers map[string]window
	entries   map[string]entry
}

// New requires fixed trusted manager configuration; nil clock selects time.Now.
// The pool is intentionally process-local; there must be one pool per manager
// admission instance. It does not preserve rate limits across restarts.
func New(b Binding, now func() time.Time) (*Pool, error) {
	return newPool(b, now, rand.Reader)
}

// MatchesBinding checks the immutable configuration of this exact pool. It
// does not establish manager authority, ownership or cross-process uniqueness.
func (p *Pool) MatchesBinding(binding Binding) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.initialized() && p.binding == binding
}

func newPool(b Binding, now func() time.Time, random io.Reader) (*Pool, error) {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		return nil, ErrInvalid
	}
	t := now().UTC()
	// Reuse the claim package's exact canonical-TLS and ID constraints.
	probe := customerclaim.Context{ManagerID: b.ManagerID, CustomerID: "customer_11111111111111111111111111111111", InstallerProfileID: "profile_11111111111111111111111111111111", Origin: b.Origin, AgentOrigin: b.AgentOrigin, IssuerFingerprint: b.IssuerFingerprint, ClaimID: "claim_11111111111111111111111111111111", Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: t.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	if !customerclaim.ValidChallengeContext(probe, t) {
		return nil, ErrInvalid
	}
	return &Pool{binding: b, now: now, random: random, last: t, peers: make(map[netip.Addr]window), customers: make(map[string]window), entries: make(map[string]entry)}, nil
}

// Issue is called only after the caller has resolved and checked the customer
// and immutable profile against current protected manager state. Those IDs are
// public but are not authority. peer must be the parsed socket RemoteAddr IP,
// never a forwarded header. The pool itself does not establish profile status.
func (p *Pool) Issue(peer, customerID, profileID, claimID string) (customerclaim.Context, error) {
	return p.issue(peer, customerID, profileID, claimID, claimPurpose)
}

// IssueStatus creates a status-only challenge. Before calling, the manager must
// resolve the original claim binding from protected state; request-supplied IDs
// alone do not establish the identity or authorize status disclosure. It shares
// all creation quotas and the same bounded pool with claim challenges.
func (p *Pool) IssueStatus(peer, customerID, profileID, claimID string) (customerclaim.Context, error) {
	return p.issue(peer, customerID, profileID, claimID, statusPurpose)
}

func (p *Pool) issue(peer, customerID, profileID, claimID string, purpose purpose) (customerclaim.Context, error) {
	if p == nil || !enrollmentcrypto.ValidID(customerID, "customer_") || !enrollmentcrypto.ValidID(profileID, "profile_") || !enrollmentcrypto.ValidID(claimID, "claim_") {
		return customerclaim.Context{}, ErrInvalid
	}
	ip, err := netip.ParseAddr(peer)
	if err != nil || ip.Zone() != "" {
		return customerclaim.Context{}, ErrInvalid
	}
	ip = ip.Unmap()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.initialized() {
		return customerclaim.Context{}, ErrUnavailable
	}
	now, err := p.timeLocked()
	if err != nil {
		return customerclaim.Context{}, err
	}
	for k, v := range p.entries {
		if v.context.ExpiresAt <= now.Unix() {
			delete(p.entries, k)
		}
	}
	for k, v := range p.peers {
		if now.Sub(v.start) >= time.Minute {
			delete(p.peers, k)
		}
	}
	for k, v := range p.customers {
		if now.Sub(v.start) >= time.Minute {
			delete(p.customers, k)
		}
	}
	if p.global.start.IsZero() || now.Sub(p.global.start) >= time.Minute {
		p.global = window{start: now}
	}
	peerWindow, hasPeer := p.peers[ip]
	customerWindow, hasCustomer := p.customers[customerID]
	if p.global.count >= GlobalPerMinute || hasPeer && peerWindow.count >= PerPeerPerMinute || hasCustomer && customerWindow.count >= PerCustomerPerMinute || !hasPeer && len(p.peers) >= MaxPeers || !hasCustomer && len(p.customers) >= MaxCustomers || len(p.entries) >= MaxOutstanding {
		return customerclaim.Context{}, ErrBusy
	}
	if !hasPeer {
		peerWindow.start = now
	}
	if !hasCustomer {
		customerWindow.start = now
	}
	p.global.count++
	peerWindow.count++
	customerWindow.count++
	p.peers[ip] = peerWindow
	p.customers[customerID] = customerWindow
	var bytes [32]byte
	if _, err = io.ReadFull(p.random, bytes[:]); err != nil {
		return customerclaim.Context{}, ErrUnavailable
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes[:])
	clear(bytes[:])
	if _, exists := p.entries[nonce]; exists {
		return customerclaim.Context{}, ErrUnavailable
	}
	c := customerclaim.Context{ManagerID: p.binding.ManagerID, CustomerID: customerID, InstallerProfileID: profileID, Origin: p.binding.Origin, AgentOrigin: p.binding.AgentOrigin, IssuerFingerprint: p.binding.IssuerFingerprint, ClaimID: claimID, Challenge: nonce, ExpiresAt: now.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	if !customerclaim.ValidChallengeContext(c, now) {
		return customerclaim.Context{}, ErrClock
	}
	p.entries[nonce] = entry{context: c, purpose: purpose}
	return c, nil
}

// Take consumes the server-stored challenge before proof validation. Competing
// calls cannot retrieve it twice, even if the caller later fails to verify the
// proof. Context is not an approval: the caller must recheck expiry, profile,
// customer and durable state at commit and must not cache this as authority.
func (p *Pool) Take(nonce string) (customerclaim.Context, error) {
	return p.take(nonce, claimPurpose)
}

// TakeStatus consumes a challenge for status verification only. Attempting to
// consume a challenge for the wrong purpose burns it without revealing context.
// The returned context does not authorize disclosure: the caller must verify
// possession and perform a fresh, protected read of the original claim.
func (p *Pool) TakeStatus(nonce string) (customerclaim.Context, error) {
	return p.take(nonce, statusPurpose)
}

func (p *Pool) take(nonce string, purpose purpose) (customerclaim.Context, error) {
	if p == nil || len(nonce) != base64.RawURLEncoding.EncodedLen(32) {
		return customerclaim.Context{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.initialized() {
		return customerclaim.Context{}, ErrUnavailable
	}
	now, err := p.timeLocked()
	if err != nil {
		// Preserve same-purpose clock recovery, but never refund a wrong-purpose
		// attempt even while the clock cannot be trusted. The same error is
		// returned either way so the purpose is not disclosed.
		if e, ok := p.entries[nonce]; ok && !e.consumed && e.purpose != purpose {
			e.consumed = true
			p.entries[nonce] = e
		}
		return customerclaim.Context{}, err
	}
	e, ok := p.entries[nonce]
	if !ok || e.consumed {
		return customerclaim.Context{}, ErrUnavailable
	}
	e.consumed = true
	p.entries[nonce] = e
	if e.purpose != purpose || !customerclaim.ValidChallengeContext(e.context, now) {
		return customerclaim.Context{}, ErrUnavailable
	}
	return e.context, nil
}

func (p *Pool) initialized() bool {
	return p.now != nil && p.random != nil && p.peers != nil && p.customers != nil && p.entries != nil && !p.last.IsZero()
}

func (p *Pool) timeLocked() (time.Time, error) {
	now := p.now().UTC()
	if now.Unix() <= 0 || now.Unix() > 253402300499 || now.Before(p.last) {
		return time.Time{}, ErrClock
	}
	p.last = now
	return now, nil
}
