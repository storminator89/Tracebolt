package enrollmenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowsnetworkcontextwire"
)

type networkContextGatedBody struct {
	io.ReadCloser
	ctx              context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (g *networkContextGatedBody) Read(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.entered)
		select {
		case <-g.release:
		case <-g.ctx.Done():
		}
	})
	return g.ReadCloser.Read(p)
}
func TestNetworkContextSeparateOriginsAndBlockedBodyAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, change := range []string{"revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsNetworkContext(context.Background()); e != nil {
					t.Fatal(e)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var block atomic.Bool
				var closeRelease sync.Once
				defer closeRelease.Do(func() { close(release) })
				h, server, client := f.listen(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if block.Load() {
							r.Body = &networkContextGatedBody{ReadCloser: r.Body, ctx: r.Context(), entered: entered, release: release}
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
				c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("d", 32), Revision: 1, Enabled: true, ChangedAt: f.now}
				message := windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c}
				raw, e := windowsnetworkcontext.EncodeMessage(message)
				if e != nil {
					t.Fatal(e)
				}
				request := func() *http.Request {
					var req *http.Request
					var e error
					if profile == "http-test" {
						req, e = windowsnetworkcontextwire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", c.Revision, time.Now().UTC(), raw)
					} else {
						req, e = http.NewRequest(http.MethodPost, server.URL+windowsnetworkcontextwire.PathPrefix+"scope", bytes.NewReader(raw))
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
					if resp.StatusCode != 403 || bytes.Contains(body, []byte(windowsnetworkcontext.ReceiptVersion)) {
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
func TestNetworkContextLastClockBeforeScopeReceiptRechecksAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		count := 0
		for _, change := range []string{"count", "revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsNetworkContext(context.Background()); e != nil {
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
				c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("e", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
				raw, e := windowsnetworkcontext.EncodeMessage(windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c})
				if e != nil {
					t.Fatal(e)
				}
				var req *http.Request
				if profile == "http-test" {
					req, e = windowsnetworkcontextwire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", 1, time.Now().UTC(), raw)
				} else {
					req, e = http.NewRequest(http.MethodPost, server.URL+windowsnetworkcontextwire.PathPrefix+"scope", bytes.NewReader(raw))
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

func TestNetworkContextComposedCompleteGenerationBothTransports(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
			ctx := context.Background()
			if e := f.store.InitializeWindowsNetworkContext(ctx); e != nil {
				t.Fatal(e)
			}
			h, server, client := f.listen(t, nil)
			at := time.Now().UTC()
			h.now = func() time.Time { return at }
			c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("a", 32), Revision: 1, Enabled: true, ChangedAt: at}
			send := func(m windowsnetworkcontext.Message) []byte {
				raw, e := windowsnetworkcontext.EncodeMessage(m)
				if e != nil {
					t.Fatal(e)
				}
				var req *http.Request
				if profile == "http-test" {
					req, e = windowsnetworkcontextwire.NewSignedRequest(ctx, server.URL, f.pair, m.Operation, m.WireSequence(), at, raw)
				} else {
					req, e = http.NewRequest("POST", server.URL+windowsnetworkcontextwire.PathPrefix+m.Operation, bytes.NewReader(raw))
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
				if _, e := windowsnetworkcontext.DecodeReceipt(body, raw); e != nil {
					t.Fatal("receipt", e)
				}
				return body
			}
			send(windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c})
			rows := make([]windowsnetworkcontext.Row, 257)
			for i := range rows {
				rows[i] = windowsnetworkcontext.Row{ID: uint32(i + 1), Kind: "route", InterfaceIndex: uint32(i%256 + 1), Route: &windowsnetworkcontext.Route{Destination: netip.MustParsePrefix(fmt.Sprintf("2001:db8::%d/128", i)).String(), NextHop: "::", Metric: uint32(i), Protocol: 2}}
			}
			messages, e := windowsnetworkcontext.Build(f.snapshot.Approval.DeviceID, c, 1, windowsnetworkcontext.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: rows})
			if e != nil {
				t.Fatal(e)
			}
			for _, m := range messages {
				first := send(m)
				if retry := send(m); !bytes.Equal(first, retry) {
					t.Fatal("retry changed receipt bytes")
				}
			}
			q := windowsnetworkcontext.Query{Kind: "route", Sort: "source-asc", Limit: 100}
			p, e := f.store.WindowsNetworkContextPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			if e != nil || p.Complete == nil || p.Complete.Manifest.RowCount != 257 || len(p.Rows) != 100 || p.Rows[0].ID != 1 || p.Rows[0].Route.Destination != "2001:db8::/128" {
				t.Fatal("transport-to-store complete page", e)
			}
			q.Search = "::256/"
			p, e = f.store.WindowsNetworkContextPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			if e != nil || p.MatchingCount != 1 || len(p.Rows) != 1 || p.Rows[0].ID != 257 {
				t.Fatal("late row missing", e)
			}
			before, _ := json.Marshal(p.Complete)
			send(windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "failure", DeviceID: f.snapshot.Approval.DeviceID, Consent: c, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"})
			p, e = f.store.WindowsNetworkContextPage(ctx, f.snapshot.Approval.DeviceID, q, at)
			after, _ := json.Marshal(p.Complete)
			if e != nil || !bytes.Equal(before, after) || p.LatestAttempt == nil || p.LatestAttempt.Status != "source_failed" {
				t.Fatal("failed transport attempt erased capture", e)
			}
		})
	}
}
