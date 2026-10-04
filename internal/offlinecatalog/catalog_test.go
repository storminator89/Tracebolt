package offlinecatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All content is invented and explicitly synthetic. These tests establish no
// real endpoint status, actual CVE applicability, or vendor-feed authenticity.
const syntheticFile = `{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["tracebolt-private-fixture-source"],"rules":[{"sourcePackage":"tracebolt-private-fixture-source","advisoryId":"CVE-2099-99990001","release":"trixie","status":"resolved","fixedVersion":"1:2.0-1+deb13u2","qualifications":[],"archiveVersions":[{"repository":"trixie-security","version":"1:2.0-1+deb13u2"}]}]}`

func testTime() time.Time { return time.Date(2026, 10, 4, 1, 0, 0, 123, time.UTC) }
func mustCandidate(t *testing.T) Candidate {
	t.Helper()
	candidate, err := Parse(context.Background(), []byte(syntheticFile), testTime())
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMetadataContractAndServerTime(t *testing.T) {
	store := New()
	initial := store.View(testTime())
	if !initial.Enabled || initial.Catalog != nil {
		t.Fatal("invalid initial view")
	}
	if !regexp.MustCompile(`^revision_[a-f0-9]{32}$`).MatchString(initial.Revision) {
		t.Fatal("invalid revision format")
	}
	if initial.Revision == New().View(testTime()).Revision {
		t.Fatal("store revisions collide")
	}
	commitTime := testTime().Add(2 * time.Minute).In(time.FixedZone("server-zone", -5*3600))
	view, err := store.Replace(context.Background(), initial.Revision, mustCandidate(t), commitTime)
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision == initial.Revision {
		t.Fatal("promotion failed to advance revision")
	}
	if view.Catalog == nil {
		t.Fatal("missing metadata")
	}
	metadata := view.Catalog
	if !regexp.MustCompile(`^catalog_[a-f0-9]{32}$`).MatchString(metadata.ID) {
		t.Fatal("invalid catalog ID")
	}
	hash := sha256.Sum256([]byte(syntheticFile))
	if metadata.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("digest not computed from exact file bytes")
	}
	if metadata.Format != "debian-tracker-normalized-1" || metadata.Provider != "debian-security-tracker" || metadata.DeclaredRelease != "trixie" {
		t.Fatal("wrong declared interchange scope")
	}
	if metadata.ByteCount != len(syntheticFile) || metadata.RuleCount != 1 || metadata.CoveredSourceCount != 1 || !metadata.Synthetic {
		t.Fatal("wrong aggregate metadata")
	}
	if !metadata.ImportedAt.Equal(commitTime) || metadata.ImportedAt.Location() != time.UTC || metadata.PublishedAt != nil || metadata.OriginAssurance != "unverified" || metadata.Freshness != "unknown" {
		t.Fatal("import time or origin/freshness changed authority")
	}
	later := store.View(testTime().Add(365 * 24 * time.Hour))
	if !later.Catalog.ImportedAt.Equal(commitTime) || later.Catalog.Freshness != "unknown" || later.Catalog.OriginAssurance != "unverified" {
		t.Fatal("read advanced time or assurance")
	}

	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	requireKeys(t, root, "schemaVersion", "enabled", "serverNow", "revision", "storage", "resetsOnRestart", "catalog", "limits")
	var catalog map[string]json.RawMessage
	if err := json.Unmarshal(root["catalog"], &catalog); err != nil {
		t.Fatal(err)
	}
	requireKeys(t, catalog, "id", "sha256", "format", "provider", "declaredRelease", "importedAt", "publishedAt", "freshness", "originAssurance", "synthetic", "byteCount", "ruleCount", "coveredSourceCount")
	var limits map[string]json.RawMessage
	if err := json.Unmarshal(root["limits"], &limits); err != nil {
		t.Fatal(err)
	}
	requireKeys(t, limits, "maxBytes", "maxRules", "maxInFlight")
	if string(catalog["publishedAt"]) != "null" || view.Storage != "memory-only" || !view.ResetsOnRestart || view.Limits != (Limits{2097152, 10000, 1}) {
		t.Fatal("missing explicit contract facts")
	}
	if bytes.Contains(encoded, []byte("tracebolt-private-fixture-source")) || bytes.Contains(encoded, []byte("CVE-2099")) || bytes.Contains(encoded, []byte("fixedVersion")) {
		t.Fatal("raw imported content in metadata view")
	}
}

func requireKeys(t *testing.T, values map[string]json.RawMessage, keys ...string) {
	t.Helper()
	if len(values) != len(keys) {
		t.Fatalf("got %d keys, want %d", len(values), len(keys))
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			t.Fatalf("missing key %s", key)
		}
	}
}

func TestZeroAndDisabledStore(t *testing.T) {
	for _, store := range []*Store{nil, {}} {
		view := store.View(testTime())
		if !reflect.DeepEqual(view, DisabledView(testTime())) || view.Enabled || view.Revision != "" || view.Catalog != nil {
			t.Fatal("uninitialized store is enabled")
		}
		_, err := store.Replace(context.Background(), "", Candidate{}, testTime())
		requireError(t, err, ErrUnavailable)
		_, err = store.Clear(context.Background(), "", testTime())
		requireError(t, err, ErrUnavailable)
	}
	encoded, err := json.Marshal(DisabledView(testTime()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"catalog":null`)) || !bytes.Contains(encoded, []byte(`"revision":""`)) {
		t.Fatal("disabled view omitted null/empty state")
	}
}

func TestCopyIsolationAndOpaqueDiagnostics(t *testing.T) {
	raw := []byte(syntheticFile)
	candidate, err := Parse(context.Background(), raw, testTime())
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if candidate.data.document.Rules[0].SourcePackage != "tracebolt-private-fixture-source" {
		t.Fatal("candidate retained mutable input")
	}
	store := New()
	copiedStore := *store
	view, err := copiedStore.Replace(context.Background(), store.View(testTime()).Revision, candidate, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if store.View(testTime()).Revision != view.Revision {
		t.Fatal("value copy split store synchronization/state")
	}
	view.Catalog.ID = "corrupted-view"
	view.Catalog.Freshness = "fresh"
	view.Catalog.OriginAssurance = "vendor_signature_verified"
	published := testTime()
	view.Catalog.PublishedAt = &published
	view.Catalog.RuleCount = 0
	fresh := store.View(testTime())
	if fresh.Catalog.ID == "corrupted-view" || fresh.Catalog.Freshness != "unknown" || fresh.Catalog.OriginAssurance != "unverified" || fresh.Catalog.PublishedAt != nil || fresh.Catalog.RuleCount != 1 {
		t.Fatal("view mutation changed retained state")
	}
	for _, value := range []any{candidate, &candidate, store, *store, struct {
		Catalog Candidate
		State   Store
	}{candidate, *store}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%#x"} {
			text := fmt.Sprintf(verb, value)
			for _, secret := range []string{"tracebolt-private-fixture-source", "CVE-2099", "1:2.0-1+deb13u2", "candidateData", "normalizedRule", "document:"} {
				if strings.Contains(text, secret) {
					t.Fatalf("diagnostics disclosed %s via %s", secret, verb)
				}
			}
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("tracebolt-private-fixture-source")) {
			t.Fatal("opaque JSON disclosed content")
		}
	}
	for _, value := range []any{Candidate{}, Store{}} {
		typeOf := reflect.TypeOf(value)
		for i := range typeOf.NumField() {
			if typeOf.Field(i).IsExported() {
				t.Fatal("opaque type has exported mutable data")
			}
		}
	}
}

func TestCASAndFailurePreserveLastGood(t *testing.T) {
	ctx := context.Background()
	store := New()
	initial := store.View(testTime())
	candidate := mustCandidate(t)
	loaded, err := store.Replace(ctx, initial.Revision, candidate, testTime())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"", initial.Revision, "revision_wrong"} {
		_, err := store.Replace(ctx, expected, candidate, testTime().Add(time.Hour))
		requireError(t, err, ErrChanged)
		_, err = store.Clear(ctx, expected, testTime().Add(time.Hour))
		requireError(t, err, ErrChanged)
	}
	_, err = store.Replace(ctx, loaded.Revision, Candidate{}, testTime().Add(time.Hour))
	requireError(t, err, ErrInvalid)
	_, err = Parse(ctx, []byte(`{"trust":"vendor_signature_verified"}`), testTime())
	requireError(t, err, ErrInvalid)
	if !reflect.DeepEqual(store.View(testTime()), loaded) {
		t.Fatal("failed mutation changed prior state")
	}
	cleared, err := store.Clear(ctx, loaded.Revision, testTime())
	if err != nil || cleared.Catalog != nil || cleared.Revision == loaded.Revision {
		t.Fatal("clear did not atomically advance revision")
	}
	again, err := store.Clear(ctx, cleared.Revision, testTime())
	if err != nil || again.Revision == cleared.Revision {
		t.Fatal("empty clear did not invalidate old revisions")
	}
}

func TestConcurrentCASReadersAndStoreValueCopies(t *testing.T) {
	store := New()
	candidate := mustCandidate(t)
	revision := store.View(testTime()).Revision
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			copied := *store
			var err error
			if i%2 == 0 {
				_, err = copied.Replace(context.Background(), revision, candidate, testTime())
			} else {
				_, err = copied.Clear(context.Background(), revision, testTime())
			}
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrChanged) {
				t.Errorf("unexpected mutation error: %v", err)
			}
		})
		wg.Go(func() {
			for range 50 {
				view := store.View(testTime())
				if view.Catalog != nil {
					view.Catalog.ID = "consumer-change"
				}
				_ = fmt.Sprintf("%#v %+v", *store, candidate)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("CAS had %d winners", winners.Load())
	}
	if store.View(testTime()).Revision == revision {
		t.Fatal("winning CAS kept old revision")
	}
}

func TestCancellationBeforeParseAndCommit(t *testing.T) {
	store := New()
	candidate := mustCandidate(t)
	loaded, err := store.Replace(context.Background(), store.View(testTime()).Revision, candidate, testTime())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	parsed, err := Parse(ctx, []byte(syntheticFile), testTime())
	requireError(t, err, context.Canceled)
	if parsed.data != nil {
		t.Fatal("canceled parse returned candidate")
	}
	_, err = store.Replace(ctx, loaded.Revision, candidate, testTime())
	requireError(t, err, context.Canceled)
	_, err = store.Clear(ctx, loaded.Revision, testTime())
	requireError(t, err, context.Canceled)
	if !reflect.DeepEqual(store.View(testTime()), loaded) {
		t.Fatal("cancellation replaced prior catalog")
	}

	for _, operation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := store.Replace(ctx, loaded.Revision, candidate, testTime())
			return err
		},
		func(ctx context.Context) error { _, err := store.Clear(ctx, loaded.Revision, testTime()); return err },
	} {
		ctx, cancel := context.WithCancel(context.Background())
		checked := make(chan struct{})
		observed := &observedContext{Context: ctx, checked: checked}
		store.state.mu.Lock()
		done := make(chan error, 1)
		go func() { done <- operation(observed) }()
		<-checked
		cancel()
		store.state.mu.Unlock()
		requireError(t, <-done, context.Canceled)
		if !reflect.DeepEqual(store.View(testTime()), loaded) {
			t.Fatal("canceled waiter committed state")
		}
	}
}

type observedContext struct {
	context.Context
	once    sync.Once
	checked chan struct{}
}

func (c *observedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

// Deterministic cancellation during parsing tests the checks between bounded
// passes and in the rule loop without a timing-dependent racing sleep.
type cancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestCancellationDuringBoundedParse(t *testing.T) {
	for _, checks := range []int{2, 6, 7, 8, 9, 10} {
		ctx, cancel := context.WithCancel(context.Background())
		ctx = &cancelAfterChecks{Context: ctx, cancel: cancel, remaining: checks}
		candidate, err := Parse(ctx, []byte(syntheticFile), testTime())
		cancel()
		if !errors.Is(err, context.Canceled) || candidate.data != nil {
			t.Fatalf("parse did not cancel at check %d", checks)
		}
	}
}
