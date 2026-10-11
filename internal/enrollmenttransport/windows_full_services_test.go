package enrollmenttransport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullserviceswire"
)

type fullServicesGatedBody struct {
	io.ReadCloser
	ctx              context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (g *fullServicesGatedBody) Read(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.entered)
		select {
		case <-g.release:
		case <-g.ctx.Done():
		}
	})
	return g.ReadCloser.Read(p)
}
func TestFullServicesSeparateOriginsAndBlockedBodyAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, change := range []string{"revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsFullServices(context.Background()); e != nil {
					t.Fatal(e)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var block atomic.Bool
				var closeRelease sync.Once
				defer closeRelease.Do(func() { close(release) })
				h, server, client := f.listen(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if block.Load() {
							r.Body = &fullServicesGatedBody{ReadCloser: r.Body, ctx: r.Context(), entered: entered, release: release}
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
				c := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: windowsfullservices.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("d", 32), Revision: 1, Enabled: true, ChangedAt: f.now}
				message := windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c}
				raw, e := windowsfullservices.EncodeMessage(message)
				if e != nil {
					t.Fatal(e)
				}
				request := func() *http.Request {
					var req *http.Request
					var e error
					if profile == "http-test" {
						req, e = windowsfullserviceswire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", c.Revision, time.Now().UTC(), raw)
					} else {
						req, e = http.NewRequest(http.MethodPost, server.URL+windowsfullserviceswire.PathPrefix+"scope", bytes.NewReader(raw))
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
					if resp.StatusCode != 403 || bytes.Contains(body, []byte(windowsfullservices.ReceiptVersion)) {
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
func TestFullServicesLastClockBeforeScopeReceiptRechecksAuthority(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		count := 0
		for _, change := range []string{"count", "revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
				if e := f.store.InitializeWindowsFullServices(context.Background()); e != nil {
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
				c := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: windowsfullservices.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("e", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
				raw, e := windowsfullservices.EncodeMessage(windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c})
				if e != nil {
					t.Fatal(e)
				}
				var req *http.Request
				if profile == "http-test" {
					req, e = windowsfullserviceswire.NewSignedRequest(context.Background(), server.URL, f.pair, "scope", 1, time.Now().UTC(), raw)
				} else {
					req, e = http.NewRequest(http.MethodPost, server.URL+windowsfullserviceswire.PathPrefix+"scope", bytes.NewReader(raw))
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
