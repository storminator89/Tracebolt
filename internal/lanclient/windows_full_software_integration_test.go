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
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsfullsoftwarewire"
)

// The memory spool and local sockets hold only invented identities/software rows.
// This is real TLS/signed-HTTP protocol execution, never a Windows host grant.
type fullSoftwareMemory struct{ files map[string][]byte }

func (s *fullSoftwareMemory) Read(n string) ([]byte, error) {
	raw, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s *fullSoftwareMemory) Write(n string, b []byte) error { s.files[n] = bytes.Clone(b); return nil }
func (s *fullSoftwareMemory) Close() error                   { return nil }

type fullSoftwareRoundTrip func(*http.Request) (*http.Response, error)

func (f fullSoftwareRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func inventedFullSoftware(n int) []windowsfullsoftware.Row {
	rows := make([]windowsfullsoftware.Row, n)
	for i := range rows {
		name, version, publisher := fmt.Sprintf("Program%05d", i), "1.0", "Publisher"
		rows[i] = windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), RegistryView: "64", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	return rows
}

func fullSoftwareSocket(t *testing.T, f *windowsManagerFixture) *http.Client {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.ingress.ServeHTTP(w, r) }))
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	if f.config.Binding.Profile == "tls" {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		now := time.Now().UTC()
		caTemplate := &x509.Certificate{SerialNumber: big.NewInt(811), Subject: pkix.Name{CommonName: "Invented full-software TLS root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
		if e != nil {
			t.Fatal(e)
		}
		ca, _ := x509.ParseCertificate(caDER)
		sp, sk, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(812), Subject: pkix.Name{CommonName: "Invented full-software TLS server"}, DNSNames: []string{"fixture.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
func fullSoftwareLocal(t *testing.T, m Material) *fullSoftwareMemory {
	t.Helper()
	st := &fullSoftwareMemory{files: map[string][]byte{}}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
	if e := windowsfullsoftware.InitializeState(st, m.config.AgentID, m.binding); e != nil {
		t.Fatal(e)
	}
	raw, e := windowsfullsoftware.EncodeConsent(c)
	if e != nil {
		t.Fatal(e)
	}
	st.Write("consent.json", raw)
	return st
}
func TestWindowsFullSoftwareRealTLSAndSignedHTTP2049LostACKRestartPages(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			ctx := context.Background()
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", profile)
			if e := f.store.InitializeWindowsFullSoftware(ctx); e != nil {
				t.Fatal(e)
			}
			client := fullSoftwareSocket(t, f)
			st := fullSoftwareLocal(t, f.material)
			calls := 0
			collect := func(context.Context) (windowsfullsoftware.Capture, error) {
				calls++
				start := time.Now().UTC()
				rows := inventedFullSoftware(2049)
				rows[2000].Name = nil
				rows[2000].NameQuality = "unavailable"
				rows[2048].Version = nil
				rows[2048].VersionQuality = "unavailable"
				rows[2048].Publisher = nil
				rows[2048].PublisherQuality = "unavailable"
				return windowsfullsoftware.Capture{StartedAt: start, FinishedAt: time.Now().UTC(), Rows: rows, Complete: true}, nil
			}
			sender, e := newFullSoftwareSender(f.material, st, func() time.Time { return time.Now().UTC() }, collect)
			if e != nil {
				t.Fatal(e)
			}
			sender.client = client
			underlying := client.Transport
			lost := false
			var lostBody, firstReceipt []byte
			replayed := false
			client.Transport = fullSoftwareRoundTrip(func(req *http.Request) (*http.Response, error) {
				body, _ := req.GetBody()
				raw, _ := io.ReadAll(body)
				body.Close()
				m, e := windowsfullsoftware.DecodeMessage(raw)
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
			if e != windowsfullsoftware.ErrTransport || report.Status != "pending_retained" || calls != 1 || !lost {
				t.Fatal("loss did not retain original capture", report, e, calls)
			}
			page, e := f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.Status != "awaiting" || len(page.Rows) != 0 || page.LatestAttempt == nil || page.LatestAttempt.Status != "pending" {
				t.Fatal("partial generation visible", e, page.Status)
			}
			// Both ends restart after an accepted chunk with a lost response.
			sender.Close()
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			f.open(t)
			sender, e = newFullSoftwareSender(f.material, st, func() time.Time { return time.Now().UTC() }, func(context.Context) (windowsfullsoftware.Capture, error) {
				t.Fatal("restart recollected")
				return windowsfullsoftware.Capture{}, nil
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
			q := windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}
			count := 0
			var first windowsfullsoftware.Page
			for {
				page, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, q, time.Now().UTC())
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
			page, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, windowsfullsoftware.Query{Search: "Program02048", Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.MatchingCount != 1 || len(page.Rows) != 1 || page.Rows[0].Version != nil {
				t.Fatal("search did not reach beyond old native cap", e)
			}
			malformed := windowsfullsoftware.Query{Sort: "name-asc", Limit: 100, Cursor: first.NextCursor + "A"}
			if _, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, malformed, time.Now().UTC()); e == nil {
				t.Fatal("malformed cursor accepted")
			}
			changed := windowsfullsoftware.Query{Search: "other", Sort: "name-asc", Limit: 100, Cursor: first.NextCursor}
			if _, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, changed, time.Now().UTC()); e == nil {
				t.Fatal("cursor query splice accepted")
			}
			ordinary, e := f.store.LatestObservations(ctx)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(ordinary)
			if bytes.Contains(raw, []byte("Program")) {
				t.Fatal("full software labels leaked into basic/AI projection")
			}
			// Local disable preserves the sender floor and synchronizes only scope state.
			c, _ := windowsfullsoftware.DecodeConsent(st.files["consent.json"])
			c.Enabled = false
			c.Revision++
			c.ChangedAt = time.Now().UTC()
			st.files["consent.json"], _ = windowsfullsoftware.EncodeConsent(c)
			report, e = sender.Burst(ctx)
			if e != nil || report.Status != "disabled" || report.Operations != 1 || sender.state.Floor() != 1 {
				t.Fatal("disable did not synchronize without capture", report, e)
			}
			page, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC())
			if e != nil || page.Status != "disabled" || page.Complete != nil || len(page.Rows) != 0 {
				t.Fatal("disabled scope still exposes rows", e)
			}
			if _, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, q, time.Now().UTC()); q.Cursor != "" && e == nil {
				t.Fatal("disabled cursor retained authority")
			}
			control := enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", 91), ExpectedRevision: f.identity.Revision, Now: time.Now().UTC().Unix()}
			if _, e = f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
				t.Fatal(e)
			}
			if _, e = f.store.WindowsFullSoftwarePage(ctx, f.material.config.AgentID, windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}, time.Now().UTC()); e == nil {
				t.Fatal("revoked identity read remained authorized")
			}
			// Request proof remains specific to this route and cannot use telemetry.
			body, _ := windowsfullsoftware.EncodeMessage(windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: f.material.config.AgentID, Consent: c})
			if profile == "http-test" {
				req, e := windowsfullsoftwarewire.NewSignedRequest(ctx, f.config.Binding.Origin, f.material.certificate, "scope", c.Revision, time.Now().UTC(), body)
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
