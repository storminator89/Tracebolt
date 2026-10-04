package journalcache

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJournalCacheBoundAndExpiryDoNotRefresh(t *testing.T) {
	c := New(nil)
	now := time.Now().UTC()
	defer func() {
		for id := range c.entries {
			c.remove(id)
		}
	}()
	for i := 0; i < MaxDevices; i++ {
		d := journalrequest.Description{Identity: journalrequest.Identity{ID: fmt.Sprint(i)}, ExpiresAt: now.Add(time.Hour)}
		if _, err := c.add(fmt.Sprint(i), d, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.add("overflow", journalrequest.Description{Identity: journalrequest.Identity{ID: "overflow"}, ExpiresAt: now.Add(time.Hour)}, now); !errors.Is(err, ErrCapacity) {
		t.Fatal("global cap not enforced")
	}
	first := c.entries["0"]
	first.raw = []byte("invented transient content")
	original := first.raw
	d := journalrequest.Description{Identity: first.identity, ExpiresAt: now.Add(2 * time.Hour)}
	again, err := c.add("0", d, now)
	if err != nil || again != first || !again.expiry.Equal(now.Add(time.Hour)) {
		t.Fatal("retry refreshed original expiry")
	}
	c.prune(now.Add(time.Hour))
	if len(c.entries) != 0 {
		t.Fatal("expired content retained")
	}
	for _, b := range original {
		if b != 0 {
			t.Fatal("removed byte buffer retained")
		}
	}
}
func TestJournalCacheAdmissionBoundsAndCancellation(t *testing.T) {
	c := New(&enrollmentstore.Store{})
	c.slots <- struct{}{}
	c.slots <- struct{}{}
	if _, err := c.lock(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded admission")
	}
	<-c.slots
	<-c.slots
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.lock(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request entered")
	}
	unlock, err := c.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if len(c.slots) != 0 {
		t.Fatal("admission slot retained")
	}
}
func TestJournalPageAndCacheDiagnosticFormattingRedacts(t *testing.T) {
	p := Page{Search: "synthetic secret", Rows: []journalview.Row{{Message: "synthetic secret"}}}
	c := New(nil)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(format, p), "synthetic secret") || strings.Contains(fmt.Sprintf(format, c), "synthetic secret") {
			t.Fatal("content diagnostics exposed")
		}
	}
}

// Synthetic authority metadata and invented rows only. The private status seam
// lets this test hold the cache mutex without holding a real store transaction.
func journalClockFixture(t *testing.T) (*Cache, *atomic.Int64, journalrequest.Status, PageRequest) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second)
	clock := &atomic.Int64{}
	clock.Store(at.UnixNano())
	c := New(&enrollmentstore.Store{}, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	q := journalview.Query{Unit: "invented.service", Start: at.Add(-time.Minute), End: at, MaxPriority: 7}
	record, err := journalrequest.New("agent_"+strings.Repeat("1", 32), strings.Repeat("a", 64), 1, q, at)
	if err != nil {
		t.Fatal(err)
	}
	snap := journalview.Snapshot{SchemaVersion: journalview.SchemaVersion, Scope: journalview.Scope, Query: q, ObservedAt: at, Coverage: journalview.Complete, Reason: journalview.ReasonNone, Rows: []journalview.Row{{Timestamp: at, Unit: q.Unit, Priority: 3, Message: "invented harmless cached row"}}, ObservedCount: 1, CountExact: true, RedactionWarning: journalview.RedactionWarning}
	raw, err := journalview.Encode(snap)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := journalview.SnapshotDigest(snap)
	receipt := journalrequest.Receipt{Identity: record.Description.Identity, PolicyDigest: "sha256:" + strings.Repeat("b", 64), ResultDigest: digest, AcceptedAt: at, ExpiresAt: record.Description.ExpiresAt}
	status := journalrequest.Status{Description: record.Description, State: journalrequest.Accepted, ContentStatus: "unavailable", Receipt: &receipt}
	c.readStatus = func(_ context.Context, _ string, now time.Time) (journalrequest.Status, error) {
		s := status
		if !now.Before(s.Description.ExpiresAt) {
			s.State = journalrequest.Expired
			s.Receipt = nil
		}
		return s, nil
	}
	e, err := c.add(record.Description.DeviceID, record.Description, at)
	if err != nil {
		t.Fatal(err)
	}
	e.raw = raw
	e.receipt = &receipt
	t.Cleanup(func() { c.mu.Lock(); defer c.mu.Unlock(); c.remove(record.Description.DeviceID) })
	return c, clock, status, PageRequest{Identity: record.Description.Identity, SnapshotDigest: digest, Search: "", Limit: 100}
}
func waitJournalAdmission(t *testing.T, c *Cache) {
	t.Helper()
	deadline := time.After(time.Second)
	for len(c.slots) == 0 {
		select {
		case <-deadline:
			t.Fatal("cache call did not enter admission")
		case <-time.After(time.Millisecond):
		}
	}
}
func TestJournalCacheQueuedPageResamplesClockAndCopiedHandleSharesLock(t *testing.T) {
	c, clock, status, q := journalClockFixture(t)
	copyHandle := *c
	if copyHandle.cacheState != c.cacheState {
		t.Fatal("cache copy detached synchronization")
	}
	type result struct {
		page Page
		err  error
	}
	done := make(chan result, 1)
	c.mu.Lock()
	go func() {
		page, err := copyHandle.Page(context.Background(), status.Description.DeviceID, q, status.Description.CreatedAt)
		done <- result{page, err}
	}()
	waitJournalAdmission(t, c)
	select {
	case <-done:
		c.mu.Unlock()
		t.Fatal("copied handle bypassed held mutex")
	default:
	}
	clock.Store(status.Description.ExpiresAt.Add(time.Second).UnixNano())
	c.mu.Unlock()
	got := <-done
	if got.err == nil || len(got.page.Rows) != 0 {
		t.Fatal("queued page released expired rows")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 0 {
		t.Fatal("expired bytes retained after queued page")
	}
}
func TestJournalCacheQueuedStatusCannotAdvertiseExpiredContent(t *testing.T) {
	c, clock, status, _ := journalClockFixture(t)
	done := make(chan journalrequest.Status, 1)
	errs := make(chan error, 1)
	c.mu.Lock()
	go func() {
		s, _, err := c.Status(context.Background(), status.Description.DeviceID, status.Description.CreatedAt)
		done <- s
		errs <- err
	}()
	waitJournalAdmission(t, c)
	clock.Store(status.Description.ExpiresAt.UnixNano())
	c.mu.Unlock()
	s := <-done
	err := <-errs
	if err != nil || s.State != journalrequest.Expired || s.ContentStatus != "unavailable" || s.Receipt != nil {
		t.Fatal("queued status advertised expired receipt/content")
	}
}
func TestJournalCacheFinalReadCrossingExpiryWithholdsPreparedPage(t *testing.T) {
	c, clock, status, q := journalClockFixture(t)
	base := c.readStatus
	reads := 0
	c.readStatus = func(ctx context.Context, device string, now time.Time) (journalrequest.Status, error) {
		reads++
		s, err := base(ctx, device, now)
		if reads == 2 {
			clock.Store(status.Description.ExpiresAt.UnixNano())
		}
		return s, err
	}
	page, err := c.Page(context.Background(), status.Description.DeviceID, q, status.Description.CreatedAt)
	if err == nil || len(page.Rows) != 0 || reads < 3 {
		t.Fatal("final authority wait released expired prepared rows")
	}
}
func TestJournalCacheCopiedHandlesShareAdmissionAndContent(t *testing.T) {
	c, _, status, _ := journalClockFixture(t)
	copyHandle := *c
	c.slots <- struct{}{}
	c.slots <- struct{}{}
	if _, _, err := copyHandle.Status(context.Background(), status.Description.DeviceID, status.Description.CreatedAt); !errors.Is(err, ErrBusy) {
		t.Fatal("copied handle escaped admission cap")
	}
	<-c.slots
	<-c.slots
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := c
			if i%2 == 0 {
				h = &copyHandle
			}
			s, _, err := h.Status(context.Background(), status.Description.DeviceID, status.Description.CreatedAt)
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Error("copy read failed")
			}
			if err == nil && s.ContentStatus != "available" {
				t.Error("copy lost shared content")
			}
		}(i)
	}
	wg.Wait()
}
