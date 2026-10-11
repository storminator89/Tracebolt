package enrollmenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullprocesseswire"
)

type fullProcessesGatedBody struct {
	io.ReadCloser
	ctx              context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (g *fullProcessesGatedBody) Read(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.entered)
		select {
		case <-g.release:
		case <-g.ctx.Done():
		}
	})
	return g.ReadCloser.Read(p)
}
func TestFullProcessesSeparateOriginsAndBlockedBodyAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, change := range []string{"revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsFullProcesses(context.Background()); e != nil {
					t.Fatal(e)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var block atomic.Bool
				var closeRelease sync.Once
				defer closeRelease.Do(func() { close(release) })
				h, server, client := f.listen(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if block.Load() {
							r.Body = &fullProcessesGatedBody{ReadCloser: r.Body, ctx: r.Context(), entered: entered, release: release}
						}
						next.ServeHTTP(w, r)
					})
				})
				var clock atomic.Int64
				clock.Store(time.Now().UTC().UnixNano())
				h.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
				if server.URL == f.config.Binding.Origin {
					t.Fatal("fixture must separate enrollment/ingress origins")
				}
				c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: windowsfullprocesses.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("d", 32), Revision: 1, Enabled: true, ChangedAt: f.now}
				message := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c}
				raw, e := windowsfullprocesses.EncodeMessage(message)
				if e != nil {
					t.Fatal(e)
				}
				request := func() *http.Request {
					var req *http.Request
					var e error
					if profile == "http-test" {
						req, e = windowsfullprocesseswire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", c.Revision, time.Now().UTC(), raw)
					} else {
						req, e = http.NewRequest(http.MethodPost, server.URL+windowsfullprocesseswire.PathPrefix+"scope", bytes.NewReader(raw))
						if e == nil {
							req.Header.Set("Content-Type", "application/json")
						}
					}
					if e != nil {
						t.Fatal(e)
					}
					return req
				}
				response(t, client, request(), 200)
				block.Store(true)
				result := make(chan *http.Response, 1)
				errs := make(chan error, 1)
				req := request()
				go func() {
					resp, e := client.Do(req)
					if e != nil {
						errs <- e
						return
					}
					result <- resp
				}()
				select {
				case <-entered:
				case e := <-errs:
					t.Fatal(e)
				case <-time.After(3 * time.Second):
					t.Fatal("body never entered bounded read")
				}
				if change == "revoked" {
					f.revoke(t)
				} else {
					clock.Store(time.Unix(f.snapshot.Intent.NotAfter, 0).UTC().UnixNano())
				}
				closeRelease.Do(func() { close(release) })
				select {
				case resp := <-result:
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 403 || bytes.Contains(body, []byte(windowsfullprocesses.ReceiptVersion)) {
						t.Fatal("post-body authority bypass", resp.StatusCode)
					}
				case e := <-errs:
					t.Fatal(e)
				case <-time.After(3 * time.Second):
					t.Fatal("blocked body did not finish")
				}
			})
		}
	}
}

// The last pre-transaction clock sample can commit revocation before the fresh
// read. Pure expiry targets the true last sample, including inside the final
// transaction, even for a scope receipt with no manifest. A revocation callback
// cannot recursively acquire the same SQLite connection from inside that read.
func TestFullProcessesLastClockBeforeScopeReceiptRechecksAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		count := 0
		for _, change := range []string{"count", "revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsFullProcesses(context.Background()); e != nil {
					t.Fatal(e)
				}
				h, server, client := f.listen(t, nil)
				calls := 0
				h.now = func() time.Time {
					calls++
					trigger := count
					if change == "revoked" {
						trigger -= 2
					} // Final guard samples after load and before COMMIT while holding SQLite.
					if change != "count" && calls == trigger {
						if change == "revoked" {
							f.revoke(t)
						} else {
							return time.Unix(f.snapshot.Intent.NotAfter, 0).UTC()
						}
					}
					return time.Now().UTC()
				}
				c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: windowsfullprocesses.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("e", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
				raw, e := windowsfullprocesses.EncodeMessage(windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c})
				if e != nil {
					t.Fatal(e)
				}
				var req *http.Request
				if profile == "http-test" {
					req, e = windowsfullprocesseswire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", 1, time.Now().UTC(), raw)
				} else {
					req, e = http.NewRequest(http.MethodPost, server.URL+windowsfullprocesseswire.PathPrefix+"scope", bytes.NewReader(raw))
					req.Header.Set("Content-Type", "application/json")
				}
				if e != nil {
					t.Fatal(e)
				}
				status := 403
				if change == "count" {
					status = 200
				}
				response(t, client, req, status)
				if change == "count" {
					count = calls
					if count < 3 {
						t.Fatal("authority clocks missing")
					}
				} else if change == "expired" && calls != count || change == "revoked" && (calls < count-2 || calls > count) {
					t.Fatal("response crossed an unchecked clock boundary", calls, count)
				}
			})
		}
	}
}

func TestFullProcessesComposedCompleteGenerationBothTransports(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
			ctx := context.Background()
			if e := f.store.InitializeWindowsFullProcesses(ctx); e != nil {
				t.Fatal(e)
			}
			h, server, client := f.listen(t, nil)
			at := time.Now().UTC()
			h.now = func() time.Time { return at }
			c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: windowsfullprocesses.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("a", 32), Revision: 1, Enabled: true, ChangedAt: at}
			send := func(m windowsfullprocesses.Message) []byte {
				raw, e := windowsfullprocesses.EncodeMessage(m)
				if e != nil {
					t.Fatal(e)
				}
				var req *http.Request
				if profile == "http-test" {
					req, e = windowsfullprocesseswire.NewSignedRequest(ctx, server.URL, f.pair, m.Operation, m.WireSequence(), at, raw)
				} else {
					req, e = http.NewRequest("POST", server.URL+windowsfullprocesseswire.PathPrefix+m.Operation, bytes.NewReader(raw))
					if e == nil {
						req.Header.Set("Content-Type", "application/json")
					}
				}
				if e != nil {
					t.Fatal(e)
				}
				resp, e := client.Do(req)
				if e != nil {
					t.Fatal(e)
				}
				body, e := io.ReadAll(resp.Body)
				resp.Body.Close()
				if e != nil || resp.StatusCode != 200 {
					t.Fatal("ingress", resp.StatusCode, e, string(body))
				}
				if _, e := windowsfullprocesses.DecodeReceipt(body, raw); e != nil {
					t.Fatal("receipt", e)
				}
				return body
			}
			send(windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c})
			rows := make([]windowsfullprocesses.Row, 257)
			for i := range rows {
				name := fmt.Sprintf("Invented process %05d", i)
				rows[i] = windowsfullprocesses.Row{PID: uint32(i), ParentPID: uint32(i / 2), Name: &name, NameQuality: "observed", Threads: uint32(i % 8)}
			}
			rows[0].Name = nil
			rows[0].NameQuality = "unavailable"
			messages, e := windowsfullprocesses.Build(f.snapshot.Approval.DeviceID, c, 1, windowsfullprocesses.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: rows})
			if e != nil {
				t.Fatal(e)
			}
			for _, m := range messages {
				first := send(m)
				if retry := send(m); !bytes.Equal(first, retry) {
					t.Fatal("retry changed receipt bytes")
				}
			}
			q := windowsfullprocesses.Query{Sort: "pid-asc", Limit: 100}
			p, e := f.store.WindowsFullProcessesPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			if e != nil || p.Complete == nil || p.Complete.Manifest.RowCount != 257 || len(p.Rows) != 100 || p.Rows[0].PID != 0 || p.Rows[0].Name != nil {
				t.Fatal("transport-to-store complete page", e)
			}
			q.Search = "00256"
			p, e = f.store.WindowsFullProcessesPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			if e != nil || p.MatchingCount != 1 || len(p.Rows) != 1 || p.Rows[0].PID != 256 {
				t.Fatal("late row missing", e)
			}
			before, _ := json.Marshal(p.Complete)
			send(windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "failure", DeviceID: f.snapshot.Approval.DeviceID, Consent: c, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"})
			p, e = f.store.WindowsFullProcessesPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			after, _ := json.Marshal(p.Complete)
			if e != nil || !bytes.Equal(before, after) || p.LatestAttempt == nil || p.LatestAttempt.Status != "source_failed" {
				t.Fatal("failed transport attempt erased capture", e)
			}
		})
	}
}
