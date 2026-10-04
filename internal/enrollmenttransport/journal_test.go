package enrollmenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
	"localrmm/internal/systemwire"
)

func (f *fixture) journalRequestFixture(t *testing.T, origin, path string, sequence uint64, body []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := journalwire.NewSignedRequest(context.Background(), origin, path, f.pair, sequence, time.Now().UTC(), body)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest(http.MethodPost, origin+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func prepareJournalTransportFixture(t *testing.T, profile string) (*fixture, *Ingress, string, *http.Client, journalrequest.Description) {
	t.Helper()
	f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
	h, server, client := f.listen(t, nil)
	at := time.Now().UTC().Add(-time.Second)
	raw, e := systemwire.Encode(1, systemSnapshotFixture(t, f.snapshot.Approval.DeviceID, 1, at))
	if e != nil {
		t.Fatal(e)
	}
	response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
	now := time.Now().UTC()
	end := now.Add(-time.Second).Truncate(time.Microsecond)
	q := journalview.Query{Unit: "invented.service", Start: end.Add(-time.Minute), End: end, MaxPriority: 7}
	d, e := h.journal.Create(context.Background(), f.snapshot.Approval.DeviceID, 0, q, now)
	if e != nil {
		t.Fatal(e)
	}
	return f, h, server.URL, client, d
}
func journalResultFixture(d journalrequest.Description, claim journalrequest.Claim, count int) journalwire.Result {
	s := journalview.Snapshot{SchemaVersion: journalview.SchemaVersion, Scope: journalview.Scope, Query: d.Query, ObservedAt: time.Now().UTC(), Coverage: journalview.Complete, Reason: journalview.ReasonNone, Rows: make([]journalview.Row, 0, count), ObservedCount: uint64(count), CountExact: true, RedactionWarning: journalview.RedactionWarning}
	for i := 0; i < count; i++ {
		text := fmt.Sprintf("invented harmless event %03d", i)
		if i%2 == 0 {
			text = fmt.Sprintf("INVENTED_JOURNAL_CONTENT_ONLY needle %03d", i)
		}
		s.Rows = append(s.Rows, journalview.Row{Timestamp: d.Query.Start.Add(time.Duration(i) * time.Microsecond), Unit: d.Query.Unit, Priority: 3, Message: text})
	}
	return journalwire.Result{Claim: claim, Snapshot: s}
}
func claimJournalFixture(t *testing.T, f *fixture, origin string, client *http.Client, d journalrequest.Description) journalrequest.Claim {
	t.Helper()
	peek, _ := journalwire.EncodePeek()
	raw := response(t, client, f.journalRequestFixture(t, origin, journalwire.PeekPath, 1, peek), 200)
	got, e := journalwire.DecodeDescription(raw)
	if e != nil || got != d {
		t.Fatal("description mismatch")
	}
	claim := journalrequest.Claim{Identity: d.Identity, PolicyDigest: "sha256:" + strings.Repeat("a", 64)}
	body, e := journalwire.EncodeClaim(claim)
	if e != nil {
		t.Fatal(e)
	}
	granted := response(t, client, f.journalRequestFixture(t, origin, journalwire.ClaimPath, d.Identity.Sequence, body), 200)
	g, e := journalwire.DecodeGrant(granted)
	if e != nil || g.Description != d || g.PolicyDigest != claim.PolicyDigest {
		t.Fatal("claim grant mismatch")
	}
	response(t, client, f.journalRequestFixture(t, origin, journalwire.ClaimPath, d.Identity.Sequence, body), 409)
	response(t, client, f.journalRequestFixture(t, origin, journalwire.PeekPath, 1, peek), 409)
	return claim
}

// Invented rows and ordinary generated identities exercise actual loopback TLS
// and signed-HTTP handlers. This test invokes no native source or local helper.
func TestJournalRealTransportResultSearchRetryAndRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, h, origin, client, d := prepareJournalTransportFixture(t, profile)
			claim := claimJournalFixture(t, f, origin, client, d)
			result := journalResultFixture(d, claim, 260)
			body, e := journalwire.EncodeResult(result)
			if e != nil {
				t.Fatal(e)
			}
			accepted := response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 200)
			receipt, e := journalwire.DecodeReceipt(accepted)
			if e != nil || receipt.Identity != d.Identity || !receipt.ExpiresAt.Equal(d.ExpiresAt) {
				t.Fatal("receipt mismatch")
			}
			retry := response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 200)
			if !bytes.Equal(accepted, retry) {
				t.Fatal("retry changed original receipt")
			}
			request := journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: receipt.ResultDigest, Search: "needle", Limit: 100}
			first, e := h.journal.Page(context.Background(), d.DeviceID, request, time.Now().UTC())
			if e != nil || first.TotalCapturedRows != 260 || first.MatchedRows != 130 || len(first.Rows) != 100 || first.NextOffset == nil || *first.NextOffset != 100 || first.SearchScope != "captured_snapshot_only" || first.ObservedAt != result.Snapshot.ObservedAt {
				t.Fatal("first search page contract", e)
			}
			request.Offset = *first.NextOffset
			second, e := h.journal.Page(context.Background(), d.DeviceID, request, time.Now().UTC())
			if e != nil || len(second.Rows) != 30 || second.NextOffset != nil || second.SnapshotDigest != first.SnapshotDigest {
				t.Fatal("second search page contract", e)
			}
			for _, p := range []journalcache.Page{first, second} {
				for _, row := range p.Rows {
					if !strings.Contains(row.Message, "needle") {
						t.Fatal("nonmatching row")
					}
				}
				b, _ := json.Marshal(p)
				if len(b) > journalview.MaxPageBytes {
					t.Fatal("page over byte cap")
				}
			}
			changed := result
			changed.Snapshot.Rows = append([]journalview.Row(nil), result.Snapshot.Rows...)
			changed.Snapshot.Rows[0].Message = "different invented content"
			other, _ := journalwire.EncodeResult(changed)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, other), 409)
			// Only authority metadata is durable, not messages or search terms.
			for _, path := range []string{f.path, f.path + "-wal"} {
				raw, e := os.ReadFile(path)
				if e != nil && !os.IsNotExist(e) {
					t.Fatal(e)
				}
				if bytes.Contains(raw, []byte("INVENTED_JOURNAL_CONTENT_ONLY")) {
					t.Fatal("content persisted in authority store")
				}
			}
			// A cache restart cannot use an exact retained-body retry to rehydrate content.
			restarted := journalcache.New(f.store)
			status, _, e := restarted.Status(context.Background(), d.DeviceID, time.Now().UTC())
			if e != nil || status.State != journalrequest.Accepted || status.ContentStatus != "unavailable" {
				t.Fatal("restart invented content", e)
			}
			again, e := restarted.Accept(context.Background(), f.snapshot.InvitationID, f.cert.CertificateHash(), d.DeviceID, result, time.Now().UTC())
			if e != nil || again != receipt {
				t.Fatal("restart receipt retry", e)
			}
			if _, e := restarted.Page(context.Background(), d.DeviceID, request, time.Now().UTC()); e != journalcache.ErrUnavailable {
				t.Fatal("restart recollected result", e)
			}
			f.revoke(t)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 403)
			if _, e := h.journal.Page(context.Background(), d.DeviceID, request, time.Now().UTC()); e == nil {
				t.Fatal("revoked page leaked")
			}
		})
	}
}
func TestJournalRealTransportPurposeAndTerminalExpiry(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, h, origin, client, d := prepareJournalTransportFixture(t, profile)
			peek, _ := journalwire.EncodePeek()
			if profile == "http-test" {
				req := f.journalRequestFixture(t, origin, journalwire.PeekPath, 1, peek)
				req.URL.Path = journalwire.ClaimPath
				response(t, client, req, 403)
			}
			malformed := []byte(`{"unexpected":true}`)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.PeekPath, 1, malformed), 400)
			claim := claimJournalFixture(t, f, origin, client, d)
			result := journalResultFixture(d, claim, 1)
			body, _ := journalwire.EncodeResult(result)
			accepted := response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 200)
			receipt, _ := journalwire.DecodeReceipt(accepted)
			later := d.ExpiresAt.Add(time.Second)
			s, _, e := h.journal.Status(context.Background(), d.DeviceID, later)
			if e != nil || s.State != journalrequest.Expired || s.Receipt != nil || s.ContentStatus != "unavailable" {
				t.Fatal("expiry metadata", e)
			}
			request := journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: receipt.ResultDigest, Limit: 10}
			if _, e := h.journal.Page(context.Background(), d.DeviceID, request, time.Now().UTC()); e == nil {
				t.Fatal("clock reversal restored content")
			}
			response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, body), 409)
		})
	}
}

// A body paused after normal peer/proof admission cannot carry a stale approval
// across revocation. No command or source is invoked by this fixture.
type journalGatedBody struct {
	io.ReadCloser
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (b *journalGatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.proceed })
	return b.ReadCloser.Read(p)
}
func TestJournalRealTransportRevocationDuringClaimBody(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			entered, proceed := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			release := func() { unblock.Do(func() { close(proceed) }) }
			defer release()
			h, server, client := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == journalwire.ClaimPath {
						r.Body = &journalGatedBody{ReadCloser: r.Body, entered: entered, proceed: proceed}
					}
					next.ServeHTTP(w, r)
				})
			})
			at := time.Now().UTC().Add(-time.Second)
			raw, e := systemwire.Encode(1, systemSnapshotFixture(t, f.snapshot.Approval.DeviceID, 1, at))
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
			now := time.Now().UTC()
			end := now.Add(-time.Second).Truncate(time.Microsecond)
			d, e := h.journal.Create(context.Background(), f.snapshot.Approval.DeviceID, 0, journalview.Query{Unit: "invented.service", Start: end.Add(-time.Minute), End: end, MaxPriority: 3}, now)
			if e != nil {
				t.Fatal(e)
			}
			claim := journalrequest.Claim{Identity: d.Identity, PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
			body, _ := journalwire.EncodeClaim(claim)
			req := f.journalRequestFixture(t, server.URL, journalwire.ClaimPath, d.Identity.Sequence, body)
			type outcome struct {
				code int
				err  error
				body []byte
			}
			done := make(chan outcome, 1)
			go func() {
				res, e := client.Do(req)
				if e != nil {
					done <- outcome{err: e}
					return
				}
				defer res.Body.Close()
				b, e := io.ReadAll(io.LimitReader(res.Body, 4097))
				done <- outcome{code: res.StatusCode, err: e, body: b}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				release()
				t.Fatal("claim never reached controlled body")
			}
			f.revoke(t)
			release()
			select {
			case got := <-done:
				if got.err != nil || got.code != 403 || bytes.Contains(got.body, []byte("claimedAt")) {
					t.Fatal("revocation failed to suppress grant", got.code, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("claim did not finish")
			}
		})
	}
}
