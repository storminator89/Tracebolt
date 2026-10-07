package proactivejournal

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"strings"
	"testing"
	"time"
)

func boundedView(now time.Time) *enrollmentstore.JournalGenerationView {
	enabled := true
	units := []string{}
	return &enrollmentstore.JournalGenerationView{SchemaVersion: "tracebolt.journal-generation-view.v3", BrowsingContract: journalview.BrowseContract, Fresh: true, ExpiresAt: now.Add(time.Minute), PolicyEnabled: &enabled, ServiceAuthorization: journalgeneration.AllSystemServices, AllowedUnits: &units, PolicyGeneration: journalgeneration.Tuple{Revision: 2, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}}
}
func TestRetainedLocalGrantNeedsExactBoundedAIApproval(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	v := boundedView(now)
	if !PermittedGeneration(v, "fixture.service", now) {
		t.Fatal("new v4 generation unavailable for independent bounded review")
	}
	for _, mutate := range []func(*enrollmentstore.JournalGenerationView){
		func(v *enrollmentstore.JournalGenerationView) { v.BrowsingContract = "" },
		func(v *enrollmentstore.JournalGenerationView) { v.BrowsingContract = "unknown" },
		func(v *enrollmentstore.JournalGenerationView) {
			v.SchemaVersion = "tracebolt.journal-generation-view.v2"
		},
		func(v *enrollmentstore.JournalGenerationView) {
			v.SchemaVersion = "tracebolt.journal-generation-view.v1"
		},
		func(v *enrollmentstore.JournalGenerationView) { v.Fresh = false },
		func(v *enrollmentstore.JournalGenerationView) { v.ExpiresAt = now },
		func(v *enrollmentstore.JournalGenerationView) { enabled := false; v.PolicyEnabled = &enabled },
	} {
		bad := *v
		mutate(&bad)
		if PermittedGeneration(&bad, "fixture.service", now) {
			t.Fatal("invalid generation admitted")
		}
	}
	legacy := *v
	legacy.SchemaVersion = "tracebolt.journal-generation-view.v2"
	legacy.BrowsingContract = ""
	if !PermittedGeneration(&legacy, "fixture.service", now) {
		t.Fatal("legacy bounded approval support lost")
	}
	s := &boundedSource{at: now, view: v}
	target := Target{DeviceID: "agent_" + strings.Repeat("1", 32), Unit: "fixture.service", Generation: v.PolicyGeneration}
	old := target
	old.Generation.Revision--
	if err := CheckTarget(context.Background(), s, old, now); !errors.Is(err, ErrChanged) {
		t.Fatal("old approval adopted new policy", err)
	}
	for _, minutes := range []int{5, 15} {
		s.record = nil
		c, err := Begin(context.Background(), s, target, now, minutes, now)
		if err != nil || c.Description.SchemaVersion != journalrequest.SchemaVersionV2 || !MatchesWindow(c, now, minutes) || c.Description.Query.BrowseMode != "" || c.Description.Query.Cursor != "" || c.Description.Query.Search != "" {
			t.Fatal("unbounded v4 capture", err)
		}
		if MatchesWindow(c, now, 20-minutes) || MatchesWindow(c, now.Add(time.Second), minutes) {
			t.Fatal("window rebound")
		}
	}
}

type boundedSource struct {
	at             time.Time
	view           *enrollmentstore.JournalGenerationView
	record         *journalrequest.Record
	page           journalcache.Page
	creates, pages int
}

func (s *boundedSource) Now() time.Time { return s.at }
func (s *boundedSource) JournalGenerationStatus(context.Context, string, time.Time) (*enrollmentstore.JournalGenerationView, error) {
	return s.view, nil
}
func (s *boundedSource) JournalStatus(context.Context, string, time.Time) (journalrequest.Status, string, error) {
	if s.record == nil {
		return journalrequest.Status{}, "", journalrequest.ErrNotFound
	}
	return journalrequest.Status{Description: s.record.Description, State: s.record.State, Receipt: s.record.Receipt, ContentStatus: "available"}, "", nil
}
func (s *boundedSource) CreateJournalRequestWithGeneration(_ context.Context, device string, floor uint64, q journalview.Query, g journalgeneration.Tuple, at time.Time) (journalrequest.Description, error) {
	s.creates++
	r, e := journalrequest.NewWithGeneration(device, strings.Repeat("c", 64), floor+1, q, g, at)
	s.record = &r
	return r.Description, e
}
func (s *boundedSource) CancelJournalRequest(context.Context, string, journalrequest.Identity, time.Time) error {
	return nil
}
func (s *boundedSource) JournalPage(context.Context, string, journalcache.PageRequest, time.Time) (journalcache.Page, error) {
	s.pages++
	return s.page, nil
}
func TestBoundedBridgeRejectsRetainedCapturesAndLiveManualPages(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	s := &boundedSource{at: now, view: boundedView(now)}
	target := Target{DeviceID: "agent_" + strings.Repeat("1", 32), Unit: "fixture.service", Generation: s.view.PolicyGeneration}
	q := journalview.Query{Unit: target.Unit, Start: time.Unix(0, 0).UTC(), End: now, MaxPriority: 4, BrowseMode: journalview.BrowseMode}
	r, e := journalrequest.NewWithGeneration(target.DeviceID, strings.Repeat("c", 64), 1, q, target.Generation, now)
	if e != nil {
		t.Fatal(e)
	}
	s.record = &r
	if _, err := Begin(context.Background(), s, target, now, 5, now); !errors.Is(err, ErrOccupied) || s.creates != 0 {
		t.Fatal("manual retained request replaced", err)
	}
	if _, err := Read(context.Background(), s, target, Capture{Description: r.Description}, now); !errors.Is(err, ErrChanged) || s.pages != 0 {
		t.Fatal("retained page adopted", err)
	}
	if err := CheckCapture(context.Background(), s, target, Capture{Description: r.Description}, "sha256:"+strings.Repeat("d", 64), now); !errors.Is(err, ErrChanged) {
		t.Fatal("retained capture revalidated", err)
	}
	s.record = nil
	c, err := Begin(context.Background(), s, target, now, 5, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Capture){
		func(c *Capture) { c.Description.ExpiresAt = c.Description.ExpiresAt.Add(time.Second) },
		func(c *Capture) { c.Description.Query.Start = now.Add(-time.Hour) },
		func(c *Capture) { c.Description.Query.Cursor = "s=fixture;i=1" },
		func(c *Capture) { c.Description.Query.Search = "source search" },
		func(c *Capture) { c.Description.Budgets.MaxRows++ },
	} {
		bad := c
		mutate(&bad)
		if _, err := Read(context.Background(), s, target, bad, now); !errors.Is(err, ErrChanged) {
			t.Fatal("forged bounded capture read", err)
		}
	}
	if s.pages != 0 {
		t.Fatal("invalid capture reached page source")
	}
}
