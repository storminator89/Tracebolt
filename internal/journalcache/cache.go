// Package journalcache holds bounded journal content solely in process memory.
// The durable store retains only request authority and an accepted digest.
package journalcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxDevices = 25
const MaxSearchBytes = 128

var ErrUnavailable = errors.New("journal_content_unavailable")
var ErrCapacity = errors.New("journal_cache_capacity")
var ErrBusy = errors.New("journal_cache_busy")

type entry struct {
	identity journalrequest.Identity
	expiry   time.Time
	receipt  *journalrequest.Receipt
	raw      []byte
	local    string
	timer    *time.Timer
}

// Cache serializes cache publication and reads around committed store receipts.
// Its buffers are not exposed, persisted, logged or reused by other pipelines.
type Cache struct{ *cacheState }

// The exported handle is safely copyable. Mutex, admission, clock, buffers and
// expiry callbacks always refer to this one private state allocation.
type cacheState struct {
	mu         sync.Mutex
	slots      chan struct{}
	store      *enrollmentstore.Store
	entries    map[string]*entry
	now        func() time.Time
	readStatus func(context.Context, string, time.Time) (journalrequest.Status, error)
}

// now is a trusted server dependency, never a timestamp from a request body.
// Omitting it selects the real clock; service/ingress wiring supplies its clock.
func New(store *enrollmentstore.Store, clocks ...func() time.Time) *Cache {
	now := time.Now
	if len(clocks) > 1 {
		return nil
	}
	if len(clocks) == 1 {
		if clocks[0] == nil {
			return nil
		}
		now = clocks[0]
	}
	state := &cacheState{store: store, entries: make(map[string]*entry), slots: make(chan struct{}, 2), now: now}
	if store != nil {
		state.readStatus = store.JournalRequestStatus
	}
	return &Cache{state}
}
func (c *Cache) Matches(s *enrollmentstore.Store) bool {
	return c != nil && c.cacheState != nil && c.store == s
}

// The earlier timestamp is also trusted. Taking the later sample prevents both
// a queued caller's stale clock and a backwards wall-clock step during this call
// from restoring expired content. Expiry remains latched by the durable store.
func (c *Cache) freshNow(earlier time.Time) time.Time {
	fresh := c.now().UTC()
	if fresh.After(earlier) {
		return fresh
	}
	return earlier.UTC()
}
func (c *Cache) remove(device string) {
	if e := c.entries[device]; e != nil {
		if e.timer != nil {
			e.timer.Stop()
		}
		clear(e.raw)
		delete(c.entries, device)
	}
}
func (c *Cache) prune(now time.Time) {
	for id, e := range c.entries {
		if !now.Before(e.expiry) {
			c.remove(id)
		}
	}
}
func (c *Cache) add(device string, d journalrequest.Description, now time.Time) (*entry, error) {
	if e := c.entries[device]; e != nil && e.identity == d.Identity {
		return e, nil
	}
	c.remove(device)
	if len(c.entries) >= MaxDevices {
		return nil, ErrCapacity
	}
	e := &entry{identity: d.Identity, expiry: d.ExpiresAt, local: "unknown"}
	c.entries[device] = e
	e.timer = time.AfterFunc(d.ExpiresAt.Sub(now), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.entries[device] == e {
			c.remove(device)
		}
	})
	return e, nil
}
func (c *Cache) Create(ctx context.Context, device string, floor uint64, q journalview.Query, now time.Time) (journalrequest.Description, error) {
	return c.CreateWithGeneration(ctx, device, floor, q, journalgeneration.Tuple{}, now)
}
func (c *Cache) CreateWithGeneration(ctx context.Context, device string, floor uint64, q journalview.Query, expected journalgeneration.Tuple, now time.Time) (journalrequest.Description, error) {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return journalrequest.Description{}, err
	}
	defer unlock()
	now = c.freshNow(now)
	c.prune(now)
	d, e := c.store.CreateJournalRequestWithGeneration(ctx, device, floor, q, expected, now)
	if e == nil {
		c.remove(device)
	}
	return d, e
}
func (c *Cache) Cancel(ctx context.Context, device string, id journalrequest.Identity, now time.Time) error {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return err
	}
	defer unlock()
	now = c.freshNow(now)
	c.prune(now)
	e := c.store.CancelJournalRequest(ctx, device, id, now)
	if e == nil || errors.Is(e, journalrequest.ErrExpired) {
		c.remove(device)
	}
	return e
}
func (c *Cache) status(ctx context.Context, device string, now time.Time) (journalrequest.Status, string, error) {
	now = c.freshNow(now)
	c.prune(now)
	s, err := c.readStatus(ctx, device, now)
	if err != nil {
		// A temporary inability to revalidate authority withholds all output,
		// but does not destroy still-live, already accepted content. Keep the
		// original timer/receipt/bytes; the next read must authorize afresh.
		// The awaited read may cross expiry while holding this mutex, so prune
		// again with trusted time even when it returns a transient error.
		c.prune(c.freshNow(now))
		if err != enrollmentstore.ErrInventoryBusy && err != enrollmentstore.ErrBusy && err != context.Canceled && err != context.DeadlineExceeded {
			c.remove(device)
		}
		return journalrequest.Status{}, "unknown", err
	}

	// Durable admission can also wait. Observe a crossing with a fresh read so
	// terminal expiry is committed before returning any availability metadata.
	after := c.freshNow(now)
	if !after.Before(s.Description.ExpiresAt) && s.State != journalrequest.Expired {
		c.remove(device)
		s, err = c.readStatus(ctx, device, after)
		if err != nil {
			return journalrequest.Status{}, "unknown", err
		}
		if s.State != journalrequest.Expired {
			return journalrequest.Status{}, "unknown", journalrequest.ErrExpired
		}
	}
	c.prune(after)
	local := "unknown"
	e := c.entries[device]
	if e != nil && (e.identity != s.Description.Identity || s.State == journalrequest.Canceled || s.State == journalrequest.Expired) {
		c.remove(device)
		e = nil
	}
	if e != nil {
		local = e.local
		if s.State == journalrequest.Accepted && s.Receipt != nil && e.receipt != nil && *e.receipt == *s.Receipt && len(e.raw) > 0 {
			s.ContentStatus = "available"
		}
	}
	return s, local, nil
}
func (c *Cache) Status(ctx context.Context, device string, now time.Time) (journalrequest.Status, string, error) {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return journalrequest.Status{}, "unknown", err
	}
	defer unlock()
	now = c.freshNow(now)
	return c.status(ctx, device, now)
}
func (c *Cache) LocalStatus(ctx context.Context, device string, in journalwire.StatusInput, now time.Time) (journalrequest.Status, error) {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return journalrequest.Status{}, err
	}
	defer unlock()
	now = c.freshNow(now)
	s, _, err := c.status(ctx, device, now)
	if err != nil {
		return journalrequest.Status{}, err
	}
	if s.Description.Identity != in.Identity {
		return journalrequest.Status{}, journalrequest.ErrConflict
	}
	if !journalwire.ValidLocalStatus(in.LocalStatus) {
		return journalrequest.Status{}, journalrequest.ErrInvalid
	}
	if in.LocalStatus != "" && s.State != journalrequest.Canceled && s.State != journalrequest.Expired {
		e, err := c.add(device, s.Description, now)
		if err != nil {
			return journalrequest.Status{}, err
		}
		e.local = in.LocalStatus
	}
	return s, nil
}

// Accept validates the entire snapshot before digest commit. A failed commit
// publishes nothing. Accepted retries return the exact original receipt; absent
// content is never rehydrated after restart/expiry/eviction from a retry.
func (c *Cache) Accept(ctx context.Context, invitation, hash, device string, in journalwire.Result, now time.Time) (journalrequest.Receipt, error) {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return journalrequest.Receipt{}, err
	}
	defer unlock()
	now = c.freshNow(now)
	s, _, err := c.status(ctx, device, now)
	if err != nil {
		return journalrequest.Receipt{}, err
	}
	if s.Description.Identity != in.Claim.Identity || s.Description.CertificateHash != hash || s.Description.Query != in.Snapshot.Query || in.Snapshot.ObservedAt.Before(s.Description.CreatedAt) || in.Snapshot.ObservedAt.After(now) || !in.Snapshot.ObservedAt.Before(s.Description.ExpiresAt) {
		return journalrequest.Receipt{}, journalrequest.ErrConflict
	}
	raw, err := journalview.Encode(in.Snapshot)
	if err != nil {
		return journalrequest.Receipt{}, journalrequest.ErrInvalid
	}
	digest, err := journalview.SnapshotDigest(in.Snapshot)
	if err != nil {
		return journalrequest.Receipt{}, journalrequest.ErrInvalid
	}
	if s.State != journalrequest.Claimed && s.State != journalrequest.Accepted {
		return journalrequest.Receipt{}, journalrequest.ErrConflict
	}
	if s.State == journalrequest.Claimed && c.entries[device] == nil && len(c.entries) >= MaxDevices {
		return journalrequest.Receipt{}, ErrCapacity
	}
	now = c.freshNow(now)
	receipt, err := c.store.AcceptJournalResult(ctx, invitation, hash, journalrequest.Result{Claim: in.Claim, ResultDigest: digest}, now)
	if err != nil {
		return journalrequest.Receipt{}, err
	}

	now = c.freshNow(now)
	if !now.Before(s.Description.ExpiresAt) {
		c.remove(device)
		_, _, _ = c.status(ctx, device, now)
		return journalrequest.Receipt{}, journalrequest.ErrExpired
	}
	if s.State == journalrequest.Claimed {
		e, err := c.add(device, s.Description, now)
		if err != nil {
			return journalrequest.Receipt{}, err
		}
		e.raw = raw
		e.receipt = &receipt
		e.local = "unknown"
	}
	return receipt, nil
}

type PageRequest struct {
	Identity       journalrequest.Identity `json:"identity"`
	SnapshotDigest string                  `json:"snapshotDigest"`
	Search         string                  `json:"search"`
	Offset         int                     `json:"offset"`
	Limit          int                     `json:"limit"`
}
type Page struct {
	SchemaVersion     string                  `json:"schemaVersion"`
	DeviceID          string                  `json:"deviceId"`
	ServerNow         time.Time               `json:"serverNow"`
	ExpiresAt         time.Time               `json:"expiresAt"`
	Identity          journalrequest.Identity `json:"identity"`
	SnapshotDigest    string                  `json:"snapshotDigest"`
	Scope             string                  `json:"scope"`
	Query             journalview.Query       `json:"query"`
	ObservedAt        time.Time               `json:"observedAt"`
	Coverage          journalview.Coverage    `json:"coverage"`
	Reason            journalview.Reason      `json:"reason"`
	Rows              []journalview.Row       `json:"rows"`
	ObservedCount     uint64                  `json:"observedCount"`
	CountExact        bool                    `json:"countExact"`
	RedactionApplied  bool                    `json:"redactionApplied"`
	RedactionWarning  string                  `json:"redactionWarning"`
	TotalCapturedRows int                     `json:"totalCapturedRows"`
	MatchedRows       int                     `json:"matchedRows"`
	Search            string                  `json:"search"`
	SearchScope       string                  `json:"searchScope"`
	Offset            int                     `json:"offset"`
	NextOffset        *int                    `json:"nextOffset"`
}

func (c *Cache) Page(ctx context.Context, device string, q PageRequest, now time.Time) (Page, error) {
	if !journalwire.ValidIdentity(q.Identity) || !journalrequest.ValidDigest(q.SnapshotDigest) || len(q.Search) > MaxSearchBytes || !utf8.ValidString(q.Search) || strings.ContainsAny(q.Search, "\x00\r\n") || q.Limit < 1 || q.Limit > journalview.MaxPageRows || q.Offset < 0 {
		return Page{}, journalrequest.ErrInvalid
	}
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		err := lockErr
		return Page{}, err
	}
	defer unlock()
	now = c.freshNow(now)
	s, _, err := c.status(ctx, device, now)
	if err != nil {
		return Page{}, err
	}
	if s.Description.Identity != q.Identity || s.Receipt == nil || s.Receipt.ResultDigest != q.SnapshotDigest {
		return Page{}, journalrequest.ErrConflict
	}
	if s.ContentStatus != "available" {
		return Page{}, ErrUnavailable
	}
	e := c.entries[device]
	var snap journalview.Snapshot
	if json.Unmarshal(e.raw, &snap) != nil {
		return Page{}, ErrUnavailable
	}
	digest, err := journalview.SnapshotDigest(snap)
	if err != nil || digest != q.SnapshotDigest {
		return Page{}, ErrUnavailable
	}
	matched := make([]journalview.Row, 0, len(snap.Rows))
	needle := strings.ToLower(q.Search)
	for _, row := range snap.Rows {
		if strings.Contains(strings.ToLower(row.Message), needle) {
			matched = append(matched, row)
		}
	}
	if q.Offset > len(matched) || q.Offset == len(matched) && q.Offset != 0 {
		return Page{}, journalrequest.ErrConflict
	}
	p := Page{SchemaVersion: "tracebolt.journal-page.v1", DeviceID: device, ServerNow: now, ExpiresAt: s.Description.ExpiresAt, Identity: q.Identity, SnapshotDigest: digest, Scope: snap.Scope, Query: snap.Query, ObservedAt: snap.ObservedAt, Coverage: snap.Coverage, Reason: snap.Reason, Rows: make([]journalview.Row, 0, q.Limit), ObservedCount: snap.ObservedCount, CountExact: snap.CountExact, RedactionApplied: snap.RedactionApplied, RedactionWarning: snap.RedactionWarning, TotalCapturedRows: len(snap.Rows), MatchedRows: len(matched), Search: q.Search, SearchScope: "captured_snapshot_only", Offset: q.Offset}
	size := 4096
	for i := q.Offset; i < len(matched) && len(p.Rows) < q.Limit; i++ {
		raw, _ := json.Marshal(matched[i])
		if size+len(raw)+1 > journalview.MaxPageBytes {
			break
		}
		p.Rows = append(p.Rows, matched[i])
		size += len(raw) + 1
	}
	if next := q.Offset + len(p.Rows); next < len(matched) {
		p.NextOffset = &next
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > journalview.MaxPageBytes {
		return Page{}, ErrCapacity
	}

	// Revalidate after snapshot decoding/search/encoding, using the shared
	// trusted clock again. No prepared rows escape if authority or TTL changed.
	final, _, err := c.status(ctx, device, c.freshNow(now))
	if err != nil {
		return Page{}, err
	}
	if final.State != journalrequest.Accepted || final.Receipt == nil || final.ContentStatus != "available" || *final.Receipt != *s.Receipt {
		return Page{}, ErrUnavailable
	}
	p.ServerNow = c.freshNow(now)
	if !p.ServerNow.Before(p.ExpiresAt) {
		c.remove(device)
		_, _, _ = c.status(ctx, device, p.ServerNow)
		return Page{}, journalrequest.ErrExpired
	}
	return p, nil
}

// At most two callers may retain in-flight cache work. Overflow fails closed
// before waiting for either the cache mutex or durable store admission.
func (c *Cache) lock(ctx context.Context) (func(), error) {
	if c == nil || c.cacheState == nil || c.store == nil || c.slots == nil || c.now == nil || c.readStatus == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		<-c.slots
		return nil, err
	}
	return func() { c.mu.Unlock(); <-c.slots }, nil
}
func (Page) String() string               { return "journalcache.Page{content redacted}" }
func (p Page) GoString() string           { return p.String() }
func (p Page) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

func (Cache) String() string               { return "journalcache.Cache{content redacted}" }
func (c Cache) GoString() string           { return c.String() }
func (c Cache) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }
