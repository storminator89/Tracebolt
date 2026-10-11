//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullserviceswire"
)

// The memory spool and local sockets hold only invented identities/service rows.
// This is real TLS/signed-HTTP protocol execution, never a Windows host grant.
type fullServicesMemory struct{ files map[string][]byte }

func (s *fullServicesMemory) Read(n string) ([]byte, error) {
	raw, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s *fullServicesMemory) Write(n string, b []byte) error { s.files[n] = bytes.Clone(b); return nil }
func (s *fullServicesMemory) Close() error                   { return nil }

type fullServicesRoundTrip func(*http.Request) (*http.Response, error)

func (f fullServicesRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func inventedFullServices(n int) []windowsfullservices.Row {
	rows := make([]windowsfullservices.Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedService%05d", i)
		display, state, pid := "Invented caller-visible service", "running", uint32(i)
		rows[i] = windowsfullservices.Row{Name: name, DisplayName: &display, DisplayNameQuality: "observed", State: &state, StateQuality: "observed", PID: &pid, PIDQuality: "observed"}
	}
	return rows
}
func fullServicesSocket(t *testing.T, f *windowsManagerFixture) *http.Client {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.ingress.ServeHTTP(w, r) }))
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	if f.config.Binding.Profile == "tls" {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		now := time.Now().UTC()
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(811), Subject: pkix.Name{CommonName: "Invented full-service TLS root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
		if e != nil {
			t.Fatal(e)
		}
		ca, _ := x509.ParseCertificate(caDER)
		sp, sk, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(812), Subject: pkix.Name{CommonName: "Invented full-service TLS server"}, DNSNames: []string{"fixture.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, sp, key)
		if e != nil {
			t.Fatal(e)
		}
		server.TLS, e = f.ingress.TLSConfig(tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: sk})
		if e != nil {
			t.Fatal(e)
		}
		server.StartTLS()
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "fixture.invalid", Certificates: []tls.Certificate{f.material.certificate}}
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func fullServicesLocal(t *testing.T, m Material) *fullServicesMemory {
	t.Helper()
	st := &fullServicesMemory{files: map[string][]byte{}}
	c := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
	if e := windowsfullservices.InitializeState(st, m.config.AgentID, m.binding); e != nil {
		t.Fatal(e)
	}
	raw, e := windowsfullservices.EncodeConsent(c)
	if e != nil {
		t.Fatal(e)
	}
	st.Write("consent.json", raw)
	return st
}
func TestWindowsFullServicesRealTLSAndSignedHTTP2049LostACKRestartPages(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			ctx := context.Background()
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", profile)
			if e := f.store.InitializeWindowsFullServices(ctx); e != nil {
				t.Fatal(e)
			}
			client := fullServicesSocket(t, f)
			st := fullServicesLocal(t, f.material)
			calls := 0
			collect := func(context.Context) (windowsfullservices.Capture, error) {
				calls++
				start := time.Now().UTC()
				rows := inventedFullServices(2049)
				rows[2000].DisplayName = nil
				rows[2000].DisplayNameQuality = "unavailable"
				rows[2048].State = nil
				rows[2048].StateQuality = "unavailable"
				rows[2048].PID = nil
				rows[2048].PIDQuality = "unavailable"
				return windowsfullservices.Capture{StartedAt: start, FinishedAt: time.Now().UTC(), Rows: rows, Complete: true}, nil
			}
			sender, e := newFullServicesSender(f.material, st, func() time.Time { return time.Now().UTC() }, collect)
			if e != nil {
				t.Fatal(e)
			}
			sender.client = client
			underlying := client.Transport
			lost := false
			var lostBody, firstReceipt []byte
			replayed := false
			client.Transport = fullServicesRoundTrip(func(req *http.Request) (*http.Response, error) {
				body, _ := req.GetBody()
				raw, _ := io.ReadAll(body)
				body.Close()
				m, e := windowsfullservices.DecodeMessage(raw)
				if e != nil {
					t.Fatal(e)
				}
				response, e := underlying.RoundTrip(req)
				if e != nil {
					return nil, e
				}
				if m.Operation == "chunk" && m.Index == 3 {
					receipt, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if !lost {
						lost = true
						lostBody = bytes.Clone(raw)
						firstReceipt = bytes.Clone(receipt)
						return nil, errors.New("invented lost acknowledgement")
					}
					if !bytes.Equal(raw, lostBody) || !bytes.Equal(receipt, firstReceipt) {
						t.Error("retry bytes/receipt changed")
					}
					replayed = true
					response.Body = io.NopCloser(bytes.NewReader(receipt))
				}
				return response, nil
			})
			report, e := sender.Burst(ctx)
			if e != windowsfullservices.ErrTransport || report.Status != "pending_retained" || calls != 1 || !lost {
				t.Fatal("loss did not retain original capture", report, e, calls)
			}
			page, e := f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, windowsfullservices.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.Status != "awaiting" || len(page.Rows) != 0 || page.LatestAttempt == nil || page.LatestAttempt.Status != "pending" {
				t.Fatal("partial generation visible", e, page.Status)
			}
			// Both ends restart after an accepted chunk with a lost response.
			sender.Close()
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			f.open(t)
			sender, e = newFullServicesSender(f.material, st, func() time.Time { return time.Now().UTC() }, func(context.Context) (windowsfullservices.Capture, error) {
				t.Fatal("restart recollected")
				return windowsfullservices.Capture{}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			sender.client = client
			report, e = sender.Burst(ctx)
			if e != nil || report.Status != "complete" || !replayed || calls != 1 || report.Sequence != 1 {
				t.Fatal("restart failed to drain exact pack", report, e)
			}
			q := windowsfullservices.Query{Sort: "name-asc", Limit: 100}
			count := 0
			var first windowsfullservices.Page
			for {
				page, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, q, time.Now().UTC())
				if e != nil || page.Status != "ready" || page.Complete == nil || page.Complete.Manifest.RowCount != 2049 || page.MatchingCount != 2049 || page.Offset != count {
					t.Fatal("paged generation incomplete", count, page.Status, e)
				}
				if count == 0 {
					first = page
				} else if page.Complete.ManifestSHA256 != first.Complete.ManifestSHA256 || !page.Complete.ReceivedAt.Equal(first.Complete.ReceivedAt) || !page.CursorExpiresAt.Equal(*first.CursorExpiresAt) {
					t.Fatal("page refreshed original metadata")
				}
				count += len(page.Rows)
				if page.NextCursor == "" {
					break
				}
				q.Cursor = page.NextCursor
			}
			if count != 2049 {
				t.Fatal("legacy row cap survived", count)
			}
			page, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, windowsfullservices.Query{Search: "Service02048", Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.MatchingCount != 1 || len(page.Rows) != 1 || page.Rows[0].State != nil {
				t.Fatal("search did not reach beyond old native cap", e)
			}
			malformed := windowsfullservices.Query{Sort: "name-asc", Limit: 100, Cursor: first.NextCursor + "A"}
			if _, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, malformed, time.Now().UTC()); e == nil {
				t.Fatal("malformed cursor accepted")
			}
			changed := windowsfullservices.Query{Search: "other", Sort: "name-asc", Limit: 100, Cursor: first.NextCursor}
			if _, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, changed, time.Now().UTC()); e == nil {
				t.Fatal("cursor query splice accepted")
			}
			ordinary, e := f.store.LatestObservations(ctx)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(ordinary)
			if bytes.Contains(raw, []byte("InventedService")) {
				t.Fatal("full service labels leaked into basic/AI projection")
			}
			// Local disable preserves the sender floor and synchronizes only scope state.
			c, _ := windowsfullservices.DecodeConsent(st.files["consent.json"])
			c.Enabled = false
			c.Revision++
			c.ChangedAt = time.Now().UTC()
			st.files["consent.json"], _ = windowsfullservices.EncodeConsent(c)
			report, e = sender.Burst(ctx)
			if e != nil || report.Status != "disabled" || report.Operations != 1 || sender.state.Floor() != 1 {
				t.Fatal("disable did not synchronize without capture", report, e)
			}
			page, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, windowsfullservices.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.Status != "disabled" || page.Complete != nil || len(page.Rows) != 0 {
				t.Fatal("disabled scope still exposes rows", e)
			}
			if _, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, q, time.Now().UTC()); q.Cursor != "" && e == nil {
				t.Fatal("disabled cursor retained authority")
			}
			control := enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", 91), ExpectedRevision: f.identity.Revision, Now: time.Now().UTC().Unix()}
			if _, e = f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
				t.Fatal(e)
			}
			if _, e = f.store.WindowsFullServicesPage(ctx, f.material.config.AgentID, windowsfullservices.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC()); e == nil {
				t.Fatal("revoked identity read remained authorized")
			}
			// Request proof remains specific to this route and cannot use telemetry.
			body, _ := windowsfullservices.EncodeMessage(windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.material.config.AgentID, Consent: c})
			if profile == "http-test" {
				req, e := windowsfullserviceswire.NewSignedRequest(ctx, f.config.Binding.Origin, f.material.certificate, "scope", c.Revision, time.Now().UTC(), body)
				if e != nil {
					t.Fatal(e)
				}
				response, e := client.Do(req)
				if e != nil {
					t.Fatal(e)
				}
				response.Body.Close()
				if response.StatusCode != 403 {
					t.Fatal("revoked signed ingress accepted", response.StatusCode)
				}
			}
		})
	}
}
