// Package windowshistorycache owns selected message bytes only in bounded process
// memory. Durable authority contains no message text and cannot refill this cache.
package windowshistorycache

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"sync"
	"time"
)

const MaxDevices = 25
const MaxEntryBytes = 512 << 10

var ErrUnavailable = errors.New("windows_history_unavailable")
var ErrSession = errors.New("windows_history_operator_session_unavailable")
var ErrClock = errors.New("windows_history_clock_regression")

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
	id      windowshistoryrequest.Identity
	owner   Owner
	expires time.Time
	raw     []byte
	stop    func() bool
	timer   *time.Timer
}
type authorityStore interface {
	CreateWindowsHistorySearch(context.Context, string, uint64, windowseventhistory.Search, time.Time) (windowshistoryrequest.Description, error)
	CreateWindowsHistoryMessages(context.Context, string, uint64, windowshistoryrequest.Receipt, windowseventhistory.Report, []windowshistoryrequest.Selection, time.Time) (windowshistoryrequest.Description, error)
	CancelWindowsHistoryRequest(context.Context, string, windowshistoryrequest.Identity, time.Time) error
	WindowsHistoryStatus(context.Context, string, time.Time) (enrollmentstore.WindowsHistoryStatus, error)
	ReportWindowsHistoryCapability(context.Context, string, string, windowshistorywire.Capability, time.Time) (windowshistorywire.Capability, error)
	PeekWindowsHistoryRequest(context.Context, string, string, time.Time) (*windowshistoryrequest.Description, error)
	ClaimWindowsHistoryRequest(context.Context, string, string, windowshistorywire.Claim, time.Time) (windowshistorywire.Grant, error)
	AcceptWindowsHistoryResult(context.Context, string, string, windowshistorywire.Result, time.Time) (windowshistoryrequest.Receipt, bool, error)
	ReportWindowsHistoryStatus(context.Context, string, string, windowshistorywire.StatusInput, time.Time) error
	AuthorizeWindowsHistoryReply(context.Context, string, string, windowshistoryrequest.Identity, time.Time) error
	MaintainWindowsHistoryAuthorities(context.Context, map[string]windowshistoryrequest.Identity, time.Time) (map[string]enrollmentstore.WindowsHistoryStatus, error)
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
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	e := c.entries[device]
	c.remove(device)
	if e == nil {
		return nil
	}
	return c.store.CancelWindowsHistoryRequest(ctx, device, e.id, now)
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
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
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
func (c *Cache) CreateSearch(ctx context.Context, device string, owner Owner, floor uint64, search windowseventhistory.Search, now time.Time) (windowshistoryrequest.Description, error) {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.create(ctx, device, owner, now, func(at time.Time) (windowshistoryrequest.Description, error) {
		return c.store.CreateWindowsHistorySearch(ctx, device, floor, search, at)
	})
}
func (c *Cache) CreateMessages(ctx context.Context, device string, owner Owner, floor uint64, receipt windowshistoryrequest.Receipt, selected []windowshistoryrequest.Selection, now time.Time) (windowshistoryrequest.Description, error) {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.create(ctx, device, owner, now, func(at time.Time) (windowshistoryrequest.Description, error) {
		s, status, err := c.status(ctx, device, &owner, at)
		if err != nil {
			return windowshistoryrequest.Description{}, err
		}
		if status != "available" || s.Request == nil || s.Request.Receipt == nil || *s.Request.Receipt != receipt || s.Request.Description.Query.Search == nil {
			return windowshistoryrequest.Description{}, ErrUnavailable
		}
		e := c.entries[device]
		if e == nil || e.owner.ID != owner.ID {
			return windowshistoryrequest.Description{}, ErrSession
		}
		result, err := windowshistorywire.DecodeResult(e.raw)
		if err != nil || windowshistorywire.ValidateResult(result, s.Request.Description) != nil {
			return windowshistoryrequest.Description{}, ErrUnavailable
		}
		fresh, err := c.currentTime(at)
		if err != nil {
			return windowshistoryrequest.Description{}, err
		}
		if !owner.valid(fresh) || !fresh.Before(e.expires) {
			return windowshistoryrequest.Description{}, ErrSession
		}
		return c.store.CreateWindowsHistoryMessages(ctx, device, floor, receipt, result.Report, selected, fresh)
	})
}
func (c *Cache) create(ctx context.Context, device string, owner Owner, now time.Time, build func(time.Time) (windowshistoryrequest.Description, error)) (windowshistoryrequest.Description, error) {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowshistoryrequest.Description{}, clockErr
	}
	if !owner.valid(now) {
		return windowshistoryrequest.Description{}, ErrSession
	}
	if len(c.entries) >= MaxDevices && c.entries[device] == nil {
		return windowshistoryrequest.Description{}, enrollmentstore.ErrWindowsHistoryCapacity
	}
	if e := c.entries[device]; e != nil && e.owner.ID != owner.ID && e.owner.valid(now) {
		return windowshistoryrequest.Description{}, ErrSession
	}
	d, err := build(now)
	if err != nil {
		return d, err
	}
	c.remove(device)
	current, err := c.store.WindowsHistoryStatus(ctx, device, c.now().UTC())
	if err != nil || current.Request == nil || current.Request.Description.Identity != d.Identity || current.Request.State != windowshistoryrequest.Pending {
		if err != nil {
			return windowshistoryrequest.Description{}, err
		}
		return windowshistoryrequest.Description{}, ErrUnavailable
	}
	now, err = c.currentTime(now)
	if err != nil {
		return windowshistoryrequest.Description{}, err
	}
	if current.LocalStatus != "enabled" || current.Capability == nil || windowshistorywire.CapabilityFresh(*current.Capability, now) != nil {
		_ = c.store.CancelWindowsHistoryRequest(ctx, device, d.Identity, now)
		return windowshistoryrequest.Description{}, ErrUnavailable
	}
	expiry := d.ExpiresAt
	if current.AuthorityUntil.Before(expiry) {
		expiry = current.AuthorityUntil
	}
	if d.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge).Before(expiry) {
		expiry = d.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)
	}
	if owner.ExpiresAt.Before(expiry) {
		expiry = owner.ExpiresAt
	}
	if !now.Before(expiry) || !owner.valid(now) {
		_ = c.store.CancelWindowsHistoryRequest(ctx, device, d.Identity, now)
		return windowshistoryrequest.Description{}, ErrSession
	}
	e := &entry{id: d.Identity, owner: owner, expires: expiry}
	c.entries[device] = e
	e.stop = context.AfterFunc(owner.Lifetime, func() { c.invalidate(device, e) })
	e.timer = time.AfterFunc(expiry.Sub(now), func() { c.invalidate(device, e) })
	if !owner.valid(c.now().UTC()) {
		_ = c.cancel(ctx, device, c.now().UTC())
		return windowshistoryrequest.Description{}, ErrSession
	}
	return d, nil
}
func (c *Cache) Cancel(ctx context.Context, device string, owner Owner, id windowshistoryrequest.Identity, now time.Time) error {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
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
		return c.store.CancelWindowsHistoryRequest(ctx, device, id, now)
	}
	e, err := c.owned(ctx, device, &owner, now)
	if err != nil {
		return err
	}
	if id != e.id {
		return windowshistoryrequest.ErrConflict
	}
	return c.cancel(ctx, device, now)
}
func (c *Cache) status(ctx context.Context, device string, owner *Owner, now time.Time) (enrollmentstore.WindowsHistoryStatus, string, error) {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return enrollmentstore.WindowsHistoryStatus{}, "unavailable", clockErr
	}
	s, err := c.store.WindowsHistoryStatus(ctx, device, now)
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
	if s.Request != nil && (!now.Before(s.Request.Description.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)) || !now.Before(s.Request.Description.ExpiresAt) && s.Request.State != windowshistoryrequest.Expired && s.Request.State != windowshistoryrequest.Canceled) {
		_ = c.cancel(ctx, device, now)
		return s, "expired", windowshistoryrequest.ErrExpired
	}
	if s.LocalStatus == "enabled" && (s.Capability == nil || windowshistorywire.CapabilityFresh(*s.Capability, now) != nil) {
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
	if s.Request.State == windowshistoryrequest.Canceled || s.Request.State == windowshistoryrequest.Expired {
		c.remove(device)
		return s, content, nil
	}
	if ownedErr != nil || e.id != s.Request.Description.Identity {
		if s.Request.State == windowshistoryrequest.Accepted {
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
	if s.Request.State == windowshistoryrequest.Accepted {
		content = "result_lost"
		if len(e.raw) > 0 {
			content = "available"
		}
	}
	return s, content, nil
}
func (c *Cache) Status(ctx context.Context, device string, owner Owner, now time.Time) (enrollmentstore.WindowsHistoryStatus, string, error) {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return enrollmentstore.WindowsHistoryStatus{}, "unavailable", clockErr
	}
	return c.status(ctx, device, &owner, now)
}
func (c *Cache) ReportCapability(ctx context.Context, device, cert string, capability windowshistorywire.Capability, now time.Time) (windowshistorywire.Capability, error) {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowshistorywire.Capability{}, clockErr
	}
	out, err := c.store.ReportWindowsHistoryCapability(ctx, device, cert, capability, now)
	if err == nil {
		_, _, _ = c.status(ctx, device, nil, now)
	}
	return out, err
}
func (c *Cache) Peek(ctx context.Context, device, cert string, now time.Time) (*windowshistoryrequest.Description, error) {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
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
	return c.store.PeekWindowsHistoryRequest(ctx, device, cert, now)
}
func (c *Cache) Claim(ctx context.Context, device, cert string, in windowshistorywire.Claim, now time.Time) (windowshistorywire.Grant, error) {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowshistorywire.Grant{}, clockErr
	}
	e, err := c.owned(ctx, device, nil, now)
	if err != nil {
		return windowshistorywire.Grant{}, err
	}
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, e.owner.ExpiresAt, func() bool { return e.owner.valid(c.now().UTC()) })
	return c.store.ClaimWindowsHistoryRequest(ctx, device, cert, in, now)
}
func (c *Cache) Accept(ctx context.Context, device, cert string, in windowshistorywire.Result, now time.Time) (windowshistoryrequest.Receipt, error) {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowshistoryrequest.Receipt{}, clockErr
	}
	if existing := c.entries[device]; existing != nil {
		if _, err := c.owned(ctx, device, nil, now); err != nil {
			return windowshistoryrequest.Receipt{}, err
		}
	} else {
		status, err := c.store.WindowsHistoryStatus(ctx, device, now)
		if err != nil {
			return windowshistoryrequest.Receipt{}, err
		}
		if status.Request == nil || status.Request.State != windowshistoryrequest.Accepted {
			return windowshistoryrequest.Receipt{}, ErrSession
		}
	}
	// Exact duplicates can return a durable receipt after cache loss, but can
	// never use that retry to reconstruct session ownership or publish bytes.
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return windowshistoryrequest.Receipt{}, clockErr
	}
	if live := c.entries[device]; live != nil {
		ctx = enrollmentstore.WithWindowsHistorySession(ctx, live.owner.ExpiresAt, func() bool { return live.owner.valid(c.now().UTC()) })
	}
	receipt, first, err := c.store.AcceptWindowsHistoryResult(ctx, device, cert, in, now)
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
	raw, err := windowshistorywire.EncodeResult(in)
	if err != nil || len(raw) > MaxEntryBytes {
		clear(raw)
		return receipt, nil
	}
	// Recheck committed authority after encoding; grant changes and original
	// header/cert/session expiry never inherit the cache's allocation lifetime.
	s, err := c.store.WindowsHistoryStatus(ctx, device, c.now().UTC())
	now, clockErr = c.currentTime(now)
	if clockErr != nil || err != nil || s.Request == nil || s.Request.State != windowshistoryrequest.Accepted || s.Request.Receipt == nil || *s.Request.Receipt != receipt || s.LocalStatus != "enabled" || s.Capability == nil || windowshistorywire.CapabilityFresh(*s.Capability, now) != nil || !e.owner.valid(now) || !now.Before(e.expires) || !now.Before(s.AuthorityUntil) {
		clear(raw)
		c.remove(device)
		return receipt, nil
	}
	clear(e.raw)
	e.raw = raw
	return receipt, nil
}

type Page struct {
	Identity  windowshistoryrequest.Identity `json:"identity"`
	Receipt   windowshistoryrequest.Receipt  `json:"receipt"`
	Report    windowshistorywire.ReportDTO   `json:"report"`
	ExpiresAt time.Time                      `json:"expiresAt"`
}

func (c *Cache) Query(ctx context.Context, device string, owner Owner, id windowshistoryrequest.Identity, now time.Time) (Page, error) {
	ctx = enrollmentstore.WithWindowsHistorySession(ctx, owner.ExpiresAt, func() bool { return owner.valid(c.now().UTC()) })
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
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
	result, err := windowshistorywire.DecodeResult(e.raw)
	if err != nil {
		c.remove(device)
		return Page{}, ErrUnavailable
	}
	digest, digestErr := windowshistorywire.ReportDigest(result.Report, s.Request.Description.Query)
	if digestErr != nil || digest != s.Request.Receipt.ResultDigest || windowshistorywire.ValidateResult(result, s.Request.Description) != nil || result.Claim.PolicyDigest != s.Request.Receipt.PolicyDigest {
		c.remove(device)
		return Page{}, ErrUnavailable
	}
	report, err := windowshistorywire.ReportForBrowser(result.Report, s.Request.Description.Query)
	if err != nil {
		return Page{}, err
	}
	return Page{id, *s.Request.Receipt, report, e.expires}, nil
}
func (c *Cache) ReportStatus(ctx context.Context, device, cert string, in windowshistorywire.StatusInput, now time.Time) error {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	err := c.store.ReportWindowsHistoryStatus(ctx, device, cert, in, now)
	if err == nil && (in.LocalStatus == "disabled" || in.LocalStatus == "expired" || in.LocalStatus == "canceled" || in.LocalStatus == "result_lost" || in.LocalStatus == "denied" || in.LocalStatus == "reader_unavailable" || in.LocalStatus == "budget_exhausted") {
		c.remove(device)
	}
	return err
}
func (c *Cache) Maintain(ctx context.Context, now time.Time) error {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
	c.mu.Lock()
	defer c.mu.Unlock()
	var clockErr error
	now, clockErr = c.currentTime(now)
	if clockErr != nil {
		return clockErr
	}
	// Snapshot exact live identities once. Never reload the complete store per
	// cached device: the production deadline also applies at the 25-device cap.
	live := make(map[string]windowshistoryrequest.Identity, len(c.entries))
	for id, e := range c.entries {
		if !e.owner.valid(now) || !now.Before(e.expires) {
			c.remove(id)
			continue
		}
		live[id] = e.id
	}
	statuses, err := c.store.MaintainWindowsHistoryAuthorities(ctx, live, now)
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
		if !now.Before(d.ExpiresAt) || !now.Before(d.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)) || s.Request.State != windowshistoryrequest.Pending && s.Request.State != windowshistoryrequest.Claimed && s.Request.State != windowshistoryrequest.Accepted {
			c.remove(id)
			continue
		}
		if s.Capability == nil || s.Capability.DeviceID != id || s.Capability.CertificateHash != d.CertificateHash || s.Capability.Consent.GrantID != d.GrantID || !s.Capability.Consent.Enabled {
			c.remove(id)
			continue
		}
		if s.LocalStatus != "enabled" || windowshistorywire.CapabilityFresh(*s.Capability, now) != nil {
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
func (c *Cache) AuthorizeReply(ctx context.Context, device, cert string, id windowshistoryrequest.Identity, now time.Time) error {
	ctx = enrollmentstore.WithWindowsHistoryClock(ctx, c.now)
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
		return windowshistoryrequest.ErrConflict
	}
	if err = c.store.AuthorizeWindowsHistoryReply(ctx, device, cert, id, now); err != nil {
		return err
	}
	s, err := c.store.WindowsHistoryStatus(ctx, device, now)
	if err != nil {
		return err
	}
	fresh := c.now().UTC()
	if fresh.Before(now) || !e.owner.valid(fresh) || !fresh.Before(e.expires) {
		return ErrSession
	}
	now = fresh
	if s.Request == nil || s.Request.Description.Identity != id || s.LocalStatus != "enabled" || s.Capability == nil || s.Request.Description.CertificateHash != s.Capability.CertificateHash || windowshistorywire.CapabilityFresh(*s.Capability, now) != nil || s.Request.Description.GrantID != s.Capability.Consent.GrantID || !now.Before(s.AuthorityUntil) || !now.Before(s.Request.Description.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge)) || s.Request.State != windowshistoryrequest.Pending && s.Request.State != windowshistoryrequest.Claimed {
		return ErrUnavailable
	}
	return nil
}
