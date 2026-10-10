// Package windowseventcache owns selected message bytes only in bounded process
// memory. Durable authority contains no message text and cannot refill this cache.
package windowseventcache

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"sync"
	"time"
)

const MaxDevices = 25
const MaxEntryBytes = 512 << 10

var ErrUnavailable = errors.New("windows_event_content_unavailable")
var ErrSession = errors.New("windows_event_operator_session_unavailable")
var ErrClock = errors.New("windows_event_clock_regression")

// Owner is supplied solely by authenticated server middleware. It is never
// decoded from a request body or persisted. Active rechecks current revocation.
type Owner struct {
	ID        string
	ExpiresAt time.Time
	Lifetime  context.Context
	Active    func() bool
}

func (o Owner) valid(now time.Time) bool {
	return o.ID != "" && o.Lifetime != nil && o.Lifetime.Err() == nil && o.Active != nil && o.Active() && now.Before(o.ExpiresAt)
}

type entry struct {
	id      windowseventrequest.Identity
	owner   Owner
	expires time.Time
	raw     []byte
	stop    func() bool
	timer   *time.Timer
}
type authorityStore interface {
	CreateWindowsEventRequest(context.Context, string, uint64, string, string, []windowseventrequest.Selection, time.Time) (windowseventrequest.Description, error)
	CancelWindowsEventRequest(context.Context, string, windowseventrequest.Identity, time.Time) error
	WindowsEventContentStatus(context.Context, string, time.Time) (enrollmentstore.WindowsEventStatus, error)
	ReportWindowsEventCapability(context.Context, string, string, windowseventwire.Capability, time.Time) (windowseventwire.Capability, error)
	PeekWindowsEventRequest(context.Context, string, string, time.Time) (*windowseventrequest.Description, error)
	ClaimWindowsEventRequest(context.Context, string, string, windowseventwire.Claim, time.Time) (windowseventwire.Grant, error)
	AcceptWindowsEventResult(context.Context, string, string, windowseventwire.Result, time.Time) (windowseventrequest.Receipt, bool, error)
	ReportWindowsEventStatus(context.Context, string, string, windowseventwire.StatusInput, time.Time) error
	MaintainWindowsEventAuthorities(context.Context, map[string]windowseventrequest.Identity, time.Time) (map[string]enrollmentstore.WindowsEventStatus, error)
}

// Cache is a safely copyable redacted handle; synchronization and bytes live
// in the one shared private state allocation.
type Cache struct{ *cacheState }
type cacheState struct {
	mu      sync.Mutex
	store   authorityStore
	now     func() time.Time
	entries map[string]*entry
	lastNow time.Time
}

func (c Cache) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("<windows event cache redacted>")) }
func New(store *enrollmentstore.Store, now func() time.Time) *Cache {
	if store == nil || now == nil {
		return nil
	}
	return &Cache{&cacheState{store: store, now: now, entries: map[string]*entry{}}}
}

// Sample only after acquiring the ownership mutex. A timestamp sampled by a
// queued caller must not be mistaken for a real wall-clock rollback. Unlike a
// max-clamp, this still rejects a genuinely backwards trusted clock.
func (c *Cache) currentTime(earlier time.Time) (time.Time, error) {
	fresh := c.now().UTC()
	if fresh.Before(earlier) || fresh.Before(c.lastNow) || fresh.Unix() <= 0 {
		for id := range c.entries {
			c.remove(id)
		}
		return time.Time{}, ErrClock
	}
	c.lastNow = fresh
	return fresh, nil
}
func (c *Cache) remove(device string) {
	if e := c.entries[device]; e != nil {
		clear(e.raw)
		e.raw = nil
		if e.stop != nil {
			e.stop()
		}
		if e.timer != nil {
			e.timer.Stop()
		}
		delete(c.entries, device)
	}
}
func (c *Cache) cancel(ctx context.Context, device string, now time.Time) error {
	e := c.entries[device]
	c.remove(device)
	if e == nil {
		return nil
	}
	return c.store.CancelWindowsEventRequest(ctx, device, e.id, now)
}
func (c *Cache) invalidate(device string, e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[device] != e {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.cancel(ctx, device, c.now().UTC())
}
func (c *Cache) owned(ctx context.Context, device string, owner *Owner, now time.Time) (*entry, error) {
	e := c.entries[device]
	if e == nil {
		return nil, ErrUnavailable
	}
	if !e.owner.valid(now) || !now.Before(e.expires) {
		_ = c.cancel(ctx, device, now)
		return nil, ErrSession
	}
	if owner != nil && (owner.ID != e.owner.ID || !owner.valid(now)) {
		return nil, ErrSession
	}
	return e, nil
}
func (c *Cache) Create(ctx context.Context, device string, owner Owner, floor uint64, generation, digest string, selected []windowseventrequest.Selection, now time.Time) (windowseventrequest.Description, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowseventrequest.Description{}, clockErr
	}
	if !owner.valid(now) {
		return windowseventrequest.Description{}, ErrSession
	}
	if len(c.entries) >= MaxDevices && c.entries[device] == nil {
		return windowseventrequest.Description{}, enrollmentstore.ErrWindowsEventCapacity
	}
	d, err := c.store.CreateWindowsEventRequest(ctx, device, floor, generation, digest, selected, now)
	if err != nil {
		return d, err
	}
	c.remove(device)
	current, err := c.store.WindowsEventContentStatus(ctx, device, c.now().UTC())
	if err != nil || current.Request == nil || current.Request.Description.Identity != d.Identity || current.Request.State != windowseventrequest.Pending {
		if err != nil {
			return windowseventrequest.Description{}, err
		}
		return windowseventrequest.Description{}, ErrUnavailable
	}
	now, err = c.currentTime(now)
	if err != nil {
		return windowseventrequest.Description{}, err
	}
	if current.LocalStatus != "enabled" || current.Capability == nil || windowseventwire.CapabilityFresh(*current.Capability, now) != nil {
		_ = c.store.CancelWindowsEventRequest(ctx, device, d.Identity, now)
		return windowseventrequest.Description{}, ErrUnavailable
	}
	expiry := d.ExpiresAt
	if current.AuthorityUntil.Before(expiry) {
		expiry = current.AuthorityUntil
	}
	if d.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge).Before(expiry) {
		expiry = d.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)
	}
	if owner.ExpiresAt.Before(expiry) {
		expiry = owner.ExpiresAt
	}
	if !now.Before(expiry) || !owner.valid(now) {
		_ = c.store.CancelWindowsEventRequest(ctx, device, d.Identity, now)
		return windowseventrequest.Description{}, ErrSession
	}
	e := &entry{id: d.Identity, owner: owner, expires: expiry}
	c.entries[device] = e
	e.stop = context.AfterFunc(owner.Lifetime, func() { c.invalidate(device, e) })
	e.timer = time.AfterFunc(expiry.Sub(now), func() { c.invalidate(device, e) })
	if !owner.valid(c.now().UTC()) {
		_ = c.cancel(ctx, device, c.now().UTC())
		return windowseventrequest.Description{}, ErrSession
	}
	return d, nil
}
func (c *Cache) Cancel(ctx context.Context, device string, owner Owner, id windowseventrequest.Identity, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	if !owner.valid(now) {
		return ErrSession
	}
	if c.entries[device] == nil {
		return c.store.CancelWindowsEventRequest(ctx, device, id, now)
	}
	e, err := c.owned(ctx, device, &owner, now)
	if err != nil {
		return err
	}
	if id != e.id {
		return windowseventrequest.ErrConflict
	}
	return c.cancel(ctx, device, now)
}
func (c *Cache) status(ctx context.Context, device string, owner *Owner, now time.Time) (enrollmentstore.WindowsEventStatus, string, error) {
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return enrollmentstore.WindowsEventStatus{}, "unavailable", clockErr
	}
	s, err := c.store.WindowsEventContentStatus(ctx, device, now)
	if err != nil {
		c.remove(device)
		return s, "unavailable", err
	}
	fresh, clockErr := c.currentTime(now)
	if clockErr != nil {
		return s, "unavailable", clockErr
	}
	now = fresh
	s.ObservedAt = now
	if !now.Before(s.AuthorityUntil) {
		c.remove(device)
		return s, "unavailable", ErrUnavailable
	}
	if s.Request != nil && (!now.Before(s.Request.Description.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)) || !now.Before(s.Request.Description.ExpiresAt) && s.Request.State != windowseventrequest.Expired && s.Request.State != windowseventrequest.Canceled) {
		_ = c.cancel(ctx, device, now)
		return s, "expired", windowseventrequest.ErrExpired
	}
	if s.LocalStatus == "enabled" && (s.Capability == nil || windowseventwire.CapabilityFresh(*s.Capability, now) != nil) {
		s.LocalStatus = "stale"
		s.Headers = nil
	}
	content := "unavailable"
	if s.Request == nil {
		c.remove(device)
		return s, content, nil
	}
	content = s.Request.State
	e, ownedErr := c.owned(ctx, device, owner, now)
	if s.Request.State == windowseventrequest.Canceled || s.Request.State == windowseventrequest.Expired {
		c.remove(device)
		return s, content, nil
	}
	if ownedErr != nil || e.id != s.Request.Description.Identity {
		if s.Request.State == windowseventrequest.Accepted {
			return s, "result_lost", nil
		}
		return s, "unavailable", nil
	}
	if s.LocalStatus != "enabled" {
		clear(e.raw)
		e.raw = nil
		return s, "unavailable", nil
	}
	if s.AuthorityUntil.Before(e.expires) {
		e.expires = s.AuthorityUntil
		if e.timer != nil {
			e.timer.Reset(e.expires.Sub(now))
		}
	}
	if !now.Before(e.expires) {
		_ = c.cancel(ctx, device, now)
		return s, "expired", nil
	}
	if s.Request.State == windowseventrequest.Accepted {
		content = "result_lost"
		if len(e.raw) > 0 {
			content = "available"
		}
	}
	return s, content, nil
}
func (c *Cache) Status(ctx context.Context, device string, owner Owner, now time.Time) (enrollmentstore.WindowsEventStatus, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return enrollmentstore.WindowsEventStatus{}, "unavailable", clockErr
	}
	return c.status(ctx, device, &owner, now)
}
func (c *Cache) ReportCapability(ctx context.Context, device, cert string, capability windowseventwire.Capability, now time.Time) (windowseventwire.Capability, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowseventwire.Capability{}, clockErr
	}
	out, err := c.store.ReportWindowsEventCapability(ctx, device, cert, capability, now)
	if err == nil {
		_, _, _ = c.status(ctx, device, nil, now)
	}
	return out, err
}
func (c *Cache) Peek(ctx context.Context, device, cert string, now time.Time) (*windowseventrequest.Description, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return nil, clockErr
	}
	if _, err := c.owned(ctx, device, nil, now); err != nil {
		return nil, nil
	}
	return c.store.PeekWindowsEventRequest(ctx, device, cert, now)
}
func (c *Cache) Claim(ctx context.Context, device, cert string, in windowseventwire.Claim, now time.Time) (windowseventwire.Grant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowseventwire.Grant{}, clockErr
	}
	if _, err := c.owned(ctx, device, nil, now); err != nil {
		return windowseventwire.Grant{}, err
	}
	return c.store.ClaimWindowsEventRequest(ctx, device, cert, in, now)
}
func (c *Cache) Accept(ctx context.Context, device, cert string, in windowseventwire.Result, now time.Time) (windowseventrequest.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowseventrequest.Receipt{}, clockErr
	}
	if existing := c.entries[device]; existing != nil {
		if _, err := c.owned(ctx, device, nil, now); err != nil {
			return windowseventrequest.Receipt{}, err
		}
	} else {
		status, err := c.store.WindowsEventContentStatus(ctx, device, now)
		if err != nil {
			return windowseventrequest.Receipt{}, err
		}
		if status.Request == nil || status.Request.State != windowseventrequest.Accepted {
			return windowseventrequest.Receipt{}, ErrSession
		}
	}
	// Exact duplicates can return a durable receipt after cache loss, but can
	// never use that retry to reconstruct session ownership or publish bytes.
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowseventrequest.Receipt{}, clockErr
	}
	receipt, first, err := c.store.AcceptWindowsEventResult(ctx, device, cert, in, now)
	if err != nil {
		return receipt, err
	}
	if !first {
		return receipt, nil
	}
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return receipt, nil
	}
	e, err := c.owned(ctx, device, nil, now)
	if err != nil {
		return receipt, nil
	}
	if e.id != receipt.Identity {
		return receipt, nil
	}
	raw, err := windowseventwire.EncodeResult(in)
	if err != nil || len(raw) > MaxEntryBytes {
		clear(raw)
		return receipt, nil
	}
	// Recheck committed authority after encoding; grant changes and original
	// header/cert/session expiry never inherit the cache's allocation lifetime.
	s, err := c.store.WindowsEventContentStatus(ctx, device, c.now().UTC())
	now, clockErr = c.currentTime(now)
	if clockErr != nil || err != nil || s.Request == nil || s.Request.State != windowseventrequest.Accepted || s.Request.Receipt == nil || *s.Request.Receipt != receipt || s.LocalStatus != "enabled" || s.Capability == nil || windowseventwire.CapabilityFresh(*s.Capability, now) != nil || !e.owner.valid(now) || !now.Before(e.expires) || !now.Before(s.AuthorityUntil) {
		clear(raw)
		c.remove(device)
		return receipt, nil
	}
	clear(e.raw)
	e.raw = raw
	return receipt, nil
}

type Page struct {
	Identity  windowseventrequest.Identity `json:"identity"`
	Receipt   windowseventrequest.Receipt  `json:"receipt"`
	Report    windowseventwire.ReportDTO   `json:"report"`
	ExpiresAt time.Time                    `json:"expiresAt"`
}

func (c *Cache) Query(ctx context.Context, device string, owner Owner, id windowseventrequest.Identity, now time.Time) (Page, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return Page{}, clockErr
	}
	s, status, err := c.status(ctx, device, &owner, now)
	if err != nil {
		return Page{}, err
	}
	if status != "available" || s.Request == nil || s.Request.Description.Identity != id || s.Request.Receipt == nil {
		return Page{}, ErrUnavailable
	}
	e := c.entries[device]
	result, err := windowseventwire.DecodeResult(e.raw)
	if err != nil {
		c.remove(device)
		return Page{}, ErrUnavailable
	}
	digest, digestErr := windowseventwire.ReportDigest(result.Report, s.Request.Description.Query)
	if digestErr != nil || digest != s.Request.Receipt.ResultDigest || windowseventwire.ValidateResult(result, s.Request.Description) != nil || result.Claim.PolicyDigest != s.Request.Receipt.PolicyDigest {
		c.remove(device)
		return Page{}, ErrUnavailable
	}
	report, err := windowseventwire.ReportForBrowser(result.Report, s.Request.Description.Query)
	if err != nil {
		return Page{}, err
	}
	return Page{id, *s.Request.Receipt, report, e.expires}, nil
}
func (c *Cache) ReportStatus(ctx context.Context, device, cert string, in windowseventwire.StatusInput, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	err := c.store.ReportWindowsEventStatus(ctx, device, cert, in, now)
	if err == nil && (in.LocalStatus == "disabled" || in.LocalStatus == "expired" || in.LocalStatus == "canceled" || in.LocalStatus == "result_lost" || in.LocalStatus == "denied" || in.LocalStatus == "reader_unavailable") {
		c.remove(device)
	}
	return err
}
func (c *Cache) Maintain(ctx context.Context, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	// Snapshot exact live identities once. Never reload the complete store per
	// cached device: the production deadline also applies at the 25-device cap.
	live := make(map[string]windowseventrequest.Identity, len(c.entries))
	for id, e := range c.entries {
		if !e.owner.valid(now) || !now.Before(e.expires) {
			c.remove(id)
			continue
		}
		live[id] = e.id
	}
	statuses, err := c.store.MaintainWindowsEventAuthorities(ctx, live, now)
	if err != nil {
		for id := range c.entries {
			c.remove(id)
		}
		return err
	}
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	for id, e := range c.entries {
		// A session or original cutoff can expire while storage is busy. Drop
		// memory immediately; the next batch retries orphan cancellation. No
		// capture/disclosure can proceed without this live memory owner.
		now, clockErr = c.currentTime(now)
		if clockErr != nil {
			return clockErr
		}
		s, ok := statuses[id]
		if !ok || !e.owner.valid(now) || !now.Before(e.expires) || !now.Before(s.AuthorityUntil) || s.Request == nil || s.Request.Description.Identity != e.id {
			c.remove(id)
			continue
		}
		d := s.Request.Description
		if !now.Before(d.ExpiresAt) || !now.Before(d.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)) || s.Request.State != windowseventrequest.Pending && s.Request.State != windowseventrequest.Claimed && s.Request.State != windowseventrequest.Accepted {
			c.remove(id)
			continue
		}
		if s.Capability == nil || s.Capability.DeviceID != id || s.Capability.CertificateHash != d.CertificateHash || s.Capability.Consent.GrantID != d.GrantID || !s.Capability.Consent.Enabled {
			c.remove(id)
			continue
		}
		if s.LocalStatus != "enabled" || windowseventwire.CapabilityFresh(*s.Capability, now) != nil {
			clear(e.raw)
			e.raw = nil
		}
		if s.AuthorityUntil.Before(e.expires) {
			e.expires = s.AuthorityUntil
			if e.timer != nil {
				e.timer.Reset(e.expires.Sub(now))
			}
		}
	}
	return nil
}
func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.entries {
		c.remove(id)
	}
}
func (c *Cache) Matches(store *enrollmentstore.Store) bool {
	return c != nil && c.cacheState != nil && c.store != nil && c.store == store
}

// AuthorizeReply is a final, non-claiming disclosure check for an authenticated
// endpoint. It compares the immutable selection rather than the latest frame.
func (c *Cache) AuthorizeReply(ctx context.Context, device, cert string, id windowseventrequest.Identity, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	e, err := c.owned(ctx, device, nil, now)
	if err != nil {
		return err
	}
	if e.id != id {
		return windowseventrequest.ErrConflict
	}
	s, err := c.store.WindowsEventContentStatus(ctx, device, now)
	if err != nil {
		return err
	}
	fresh := c.now().UTC()
	if fresh.Before(now) || !e.owner.valid(fresh) || !fresh.Before(e.expires) {
		return ErrSession
	}
	now = fresh
	if s.Request == nil || s.Request.Description.Identity != id || s.Request.Description.CertificateHash != cert || s.LocalStatus != "enabled" || s.Capability == nil || s.Capability.CertificateHash != cert || windowseventwire.CapabilityFresh(*s.Capability, now) != nil || s.Request.Description.GrantID != s.Capability.Consent.GrantID || !now.Before(s.AuthorityUntil) || !now.Before(s.Request.Description.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge)) || s.Request.State != windowseventrequest.Pending && s.Request.State != windowseventrequest.Claimed {
		return ErrUnavailable
	}
	return nil
}
