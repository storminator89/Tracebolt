//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"localrmm/internal/windowshistorywire"
	"localrmm/internal/windowshistoryworker"
)

type historyFixture struct {
	s                                     *windowsEventHistorySender
	memory                                *eventMemory
	c                                     windowshistoryrequest.Consent
	r                                     windowshistoryrequest.Record
	now                                   time.Time
	captures, claims                      int
	results, capabilities                 [][]byte
	lostResult, lostClaim, lostCapability bool
	localErr                              error
}

func historyFixtureFor(t *testing.T, profile string) *historyFixture {
	t.Helper()
	m := windowsMaterialFixture(t, profile)
	now := time.Now().UTC().Truncate(time.Second)
	local := windowsEventHistoryContext(m)
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Profile: profile, Enabled: true, ContentAcknowledged: true, HistoryAcknowledged: true, HTTPPlaintextAcknowledged: profile == "http-test"}
	search := windowseventhistory.Search{Channel: "Application", Start: now.Add(-24 * time.Hour), End: now.Add(-time.Minute)}
	r, e := windowshistoryrequest.NewSearch(local.DeviceID, local.CertificateHash, 8, c.GrantID, search, now.Add(-2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	reports, _ := windowshistorystate.NewReports(local)
	raw, _ := windowshistorystate.EncodeReports(reports)
	consumed, _ := windowshistorystate.NewConsumption(local)
	con, _ := windowshistorystate.EncodeConsumption(consumed)
	f := &historyFixture{c: c, r: r, now: now, memory: &eventMemory{values: map[string][]byte{"reports.json": raw, "consumed.json": con}}}
	f.s = &windowsEventHistorySender{material: m, now: func() time.Time { return f.now }, local: func(Material) (windowshistoryrequest.Consent, error) { return f.c, f.localErr }, metadata: func(_ Material, c windowshistoryrequest.Consent, fn func(windowshistorystate.Storage) error) error {
		if c != f.c {
			return ErrState
		}
		return fn(f.memory)
	}}
	f.s.collect = func(_ context.Context, r windowshistoryworker.Request) (windowseventhistory.Report, error) {
		if windowshistorystate.VerifyAttempt(f.memory, r.Local, r.Description, r.PolicyDigest) != nil {
			t.Fatal("child launched before durable attempt")
		}
		if e := windowshistorystate.Consume(f.memory, r.Local, r.Description, r.Consent, r.PolicyDigest, f.now); e != nil {
			return windowseventhistory.Report{}, e
		}
		f.captures++
		report := windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: windowseventhistory.QualityObserved, CollectedAt: f.now, Complete: true, Events: []windowseventhistory.Result{}}
		if r.Description.Query.Search != nil {
			report.Search = windowseventhistory.CloneSearch(r.Description.Query.Search)
			report.Events = append(report.Events, windowseventhistory.Result{Event: windowseventhistory.Event{Channel: "Application", RecordID: 18446744073709551615, EventID: 3, Level: 2, Provider: "Synthetic", Timestamp: f.now.Add(-time.Hour)}, Quality: windowseventhistory.QualityObserved, Complete: true})
		} else {
			report.Events = append(report.Events, windowseventhistory.Result{Event: r.Description.Query.Events[0], Message: "synthetic-secret-content-marker", Quality: windowseventhistory.QualityObserved, Complete: true})
		}

		return report, nil
	}
	f.s.exchange = func(_ context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
		switch path {
		case windowshistorywire.CapabilityPath:
			f.capabilities = append(f.capabilities, bytes.Clone(body))
			if f.lostCapability {
				f.lostCapability = false
				return nil, 0, ErrTransport
			}
			return bytes.Clone(body), http.StatusOK, nil
		case windowshistorywire.PeekPath:
			b, _ := windowshistorywire.EncodeDescription(f.r.Description)
			return b, http.StatusOK, nil
		case windowshistorywire.ClaimPath:
			f.claims++
			claim, e := windowshistorywire.DecodeClaim(body)
			if e != nil || sequence != claim.Identity.Sequence {
				t.Fatal("invalid claim")
			}
			var err error
			f.r, err = windowshistoryrequest.Claim(f.r, claim.Identity, f.c, local, f.now.Add(-time.Second))
			if err != nil {
				t.Fatal("manager double claim")
			}
			if f.lostClaim {
				return nil, 0, ErrTransport
			}
			grant, _ := windowshistorywire.GrantFor(f.r)
			b, _ := windowshistorywire.EncodeGrant(grant)
			return b, http.StatusOK, nil
		case windowshistorywire.ResultPath:
			f.results = append(f.results, bytes.Clone(body))
			if f.lostResult {
				f.lostResult = false
				return nil, 0, ErrTransport
			}
			result, e := windowshistorywire.DecodeResult(body)
			if e != nil {
				t.Fatal(e)
			}
			accepted, e := windowshistoryrequest.Accept(f.r, result.Claim.Identity, f.c, local, result.Report, f.now)
			if e != nil {
				t.Fatal(e)
			}
			f.r = accepted
			b, _ := windowshistorywire.EncodeReceipt(*accepted.Receipt)
			return b, http.StatusOK, nil
		case windowshistorywire.StatusPath:
			if _, e := windowshistorywire.DecodeStatusInput(body); e != nil {
				t.Fatal(e)
			}
			return []byte("{}"), http.StatusOK, nil
		}
		t.Fatal("unexpected path", path)
		return nil, 0, ErrTransport
	}
	t.Cleanup(f.s.Close)
	return f
}
func TestWindowsEventHistoryPipelineExactRetryAndNoDurableContent(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := historyFixtureFor(t, profile)
			f.lostResult = true
			if got := f.s.Run(context.Background()); got != "pending_retained" {
				t.Fatal(got)
			}
			if f.captures != 1 || f.claims != 1 || f.s.pending == nil {
				t.Fatal("capture missing")
			}
			f.now = f.now.Add(time.Second)
			if got := f.s.Run(context.Background()); got != "acknowledged" {
				t.Fatal(got)
			}
			if f.captures != 1 || f.claims != 1 || len(f.results) != 2 || !bytes.Equal(f.results[0], f.results[1]) || f.s.pending != nil {
				t.Fatal("result recaptured or retry changed")
			}
			for _, raw := range f.memory.values {
				if bytes.Contains(raw, []byte("synthetic-secret")) || bytes.Contains(raw, []byte("Synthetic")) {
					t.Fatal("content/header persisted")
				}
			}
		})
	}
}
func TestWindowsEventHistoryNoGrantAndDisableNeverRead(t *testing.T) {
	for _, mode := range []string{"missing", "denied", "disabled", "replaced"} {
		f := historyFixtureFor(t, "http-test")
		switch mode {
		case "missing":
			f.localErr = errEventHistoryDisabled
		case "denied":
			f.localErr = ErrState
		case "disabled":
			f.c.Enabled = false
		case "replaced":
			f.c.GrantID = strings.Repeat("7", 32)
		}
		f.s.Run(context.Background())
		if f.captures != 0 || f.claims != 0 {
			t.Fatal(mode, "read without exact grant")
		}
	}
}
func TestWindowsEventHistoryLostClaimAndRestartNeverCapture(t *testing.T) {
	f := historyFixtureFor(t, "http-test")
	f.lostClaim = true
	if got := f.s.Run(context.Background()); got != "result_lost" {
		t.Fatal(got)
	}
	f.lostClaim = false
	if got := f.s.Run(context.Background()); got != "result_lost" {
		t.Fatal(got)
	}
	if f.captures != 0 || f.claims != 1 {
		t.Fatal("ambiguous claim retried")
	}
	f = historyFixtureFor(t, "tls")
	f.lostResult = true
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("missing result")
	}
	f.s.Close()
	if got := f.s.Run(context.Background()); got != "result_lost" {
		t.Fatal(got)
	}
	if f.captures != 1 || f.claims != 1 {
		t.Fatal("restart recaptured")
	}
}
func TestWindowsEventHistorySelectedFollowupKeepsOriginalExpiry(t *testing.T) {
	f := historyFixtureFor(t, "tls")
	if f.s.Run(context.Background()) != "acknowledged" {
		t.Fatal("history search failed")
	}
	result, e := windowshistorywire.DecodeResult(f.results[0])
	if e != nil {
		t.Fatal(e)
	}
	expiry := f.r.Description.ExpiresAt
	f.now = f.now.Add(2 * time.Second)
	f.r, e = windowshistoryrequest.NewMessages(f.r.Description.DeviceID, f.r.Description.CertificateHash, f.r.Description.Identity.Sequence+1, f.c.GrantID, f.r, result.Report, []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, f.now.Add(-time.Second))
	if e != nil || f.r.Description.ExpiresAt != expiry {
		t.Fatal("followup refreshed original expiry", e)
	}
	f.lostResult = true
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("followup not retained")
	}
	f.now = f.now.Add(time.Second)
	if f.s.Run(context.Background()) != "acknowledged" || f.captures != 2 || f.claims != 2 || !bytes.Equal(f.results[1], f.results[2]) {
		t.Fatal("followup reread or changed")
	}
	for _, raw := range f.memory.values {
		if bytes.Contains(raw, []byte("synthetic-secret")) || bytes.Contains(raw, []byte("Synthetic")) {
			t.Fatal("history content persisted")
		}
	}
}
func TestWindowsEventHistoryEmptySearchAndRevokedPending(t *testing.T) {
	f := historyFixtureFor(t, "tls")
	collect := f.s.collect
	f.s.collect = func(ctx context.Context, r windowshistoryworker.Request) (windowseventhistory.Report, error) {
		report, e := collect(ctx, r)
		report.Events = []windowseventhistory.Result{}
		return report, e
	}
	if f.s.Run(context.Background()) != "acknowledged" || f.captures != 1 {
		t.Fatal("empty observed search rejected")
	}
	f = historyFixtureFor(t, "tls")
	f.lostResult = true
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("result not retained")
	}
	f.c.Enabled = false
	if f.s.Run(context.Background()) != "disabled" || f.s.pending != nil || f.captures != 1 {
		t.Fatal("disabled pending result survived")
	}
}

// A hard owned-worker timeout is finite status metadata, never a successful
// empty search or a fresh permit to consume the same source request again.
func TestWindowsEventHistoryHardWorkerBudgetRemainsExplicit(t *testing.T) {
	for _, budget := range []bool{false, true} {
		f := historyFixtureFor(t, "tls")
		collect, exchange := f.s.collect, f.s.exchange
		seen := ""
		f.s.collect = func(ctx context.Context, r windowshistoryworker.Request) (windowseventhistory.Report, error) {
			if _, e := collect(ctx, r); e != nil {
				return windowseventhistory.Report{}, e
			}
			if budget {
				return windowseventhistory.Report{}, errors.Join(windowshistoryworker.ErrBudget, errors.New("synthetic private worker detail"))
			}
			return windowseventhistory.Report{}, windowshistoryworker.ErrUnavailable
		}
		f.s.exchange = func(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
			if path == windowshistorywire.StatusPath {
				value, e := windowshistorywire.DecodeStatusInput(body)
				if e != nil {
					t.Fatal("invalid finite status", e)
				}
				seen = value.LocalStatus
				if bytes.Contains(body, []byte("private worker detail")) {
					t.Fatal("worker prose escaped")
				}
			}
			return exchange(ctx, path, sequence, body)
		}
		want := "reader_unavailable"
		if budget {
			want = "budget_exhausted"
		}
		if got := f.s.Run(context.Background()); got != want || seen != want || f.captures != 1 || f.claims != 1 || len(f.results) != 0 || f.s.pending != nil {
			t.Fatal("worker outcome hidden or fabricated", got, seen)
		}
		if got := f.s.Run(context.Background()); got != "result_lost" || f.captures != 1 || f.claims != 1 {
			t.Fatal("worker failure recaptured", got)
		}
	}
}
