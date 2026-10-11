//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowseventworker"
)

type eventMemory struct {
	values map[string][]byte
	writes int
	fail   bool
}

func (m *eventMemory) Read(n string) ([]byte, error) {
	b, ok := m.values[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (m *eventMemory) Write(n string, b []byte) error {
	m.writes++
	if m.fail {
		return ErrState
	}
	m.values[n] = bytes.Clone(b)
	return nil
}

type eventFixture struct {
	s                                     *windowsEventContentSender
	memory                                *eventMemory
	c                                     windowseventrequest.Consent
	r                                     windowseventrequest.Record
	now                                   time.Time
	captures, claims                      int
	results, capabilities                 [][]byte
	lostResult, lostClaim, lostCapability bool
	localErr                              error
}

func eventFixtureFor(t *testing.T, profile string) *eventFixture {
	t.Helper()
	m := windowsMaterialFixture(t, profile)
	now := time.Now().UTC().Truncate(time.Second)
	local := windowsEventContentContext(m)
	c := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Profile: profile, Enabled: true, ContentAcknowledged: true, HTTPPlaintextAcknowledged: profile == "http-test"}
	h := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("d", 32), GenerationID: "sample_" + strings.Repeat("e", 32), CollectedAt: now.Add(-time.Minute), Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 3, Level: 2, Provider: "Synthetic", Timestamp: now.Add(-time.Minute)}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	r, e := windowseventrequest.New(local.DeviceID, local.CertificateHash, 8, c.GrantID, h, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, now.Add(-2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	reports, _ := windowseventstate.NewReports(local)
	raw, _ := windowseventstate.EncodeReports(reports)
	consumed, _ := windowseventstate.NewConsumption(local)
	con, _ := windowseventstate.EncodeConsumption(consumed)
	f := &eventFixture{c: c, r: r, now: now, memory: &eventMemory{values: map[string][]byte{"reports.json": raw, "consumed.json": con}}}
	f.s = &windowsEventContentSender{material: m, now: func() time.Time { return f.now }, local: func(Material) (windowseventrequest.Consent, error) { return f.c, f.localErr }, metadata: func(_ Material, c windowseventrequest.Consent, fn func(windowseventstate.Storage) error) error {
		if c != f.c {
			return ErrState
		}
		return fn(f.memory)
	}}
	f.s.collect = func(_ context.Context, r windowseventworker.Request) (windowseventcontent.Report, error) {
		if windowseventstate.VerifyAttempt(f.memory, r.Local, r.Description, r.PolicyDigest) != nil {
			t.Fatal("child launched before durable attempt")
		}
		if e := windowseventstate.Consume(f.memory, r.Local, r.Description, r.Consent, r.PolicyDigest, f.now); e != nil {
			return windowseventcontent.Report{}, e
		}
		f.captures++
		report := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: windowseventcontent.QualityObserved, CollectedAt: f.now, Complete: true, Events: []windowseventcontent.Result{{Event: r.Description.Query.Events[0], Message: "synthetic-secret-content-marker", Quality: windowseventcontent.QualityObserved, Complete: true}}}
		return report, nil
	}
	f.s.exchange = func(_ context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
		switch path {
		case windowseventwire.CapabilityPath:
			f.capabilities = append(f.capabilities, bytes.Clone(body))
			if f.lostCapability {
				f.lostCapability = false
				return nil, 0, ErrTransport
			}
			return bytes.Clone(body), http.StatusOK, nil
		case windowseventwire.PeekPath:
			b, _ := windowseventwire.EncodeDescription(f.r.Description)
			return b, http.StatusOK, nil
		case windowseventwire.ClaimPath:
			f.claims++
			claim, e := windowseventwire.DecodeClaim(body)
			if e != nil || sequence != claim.Identity.Sequence {
				t.Fatal("invalid claim")
			}
			var err error
			f.r, err = windowseventrequest.Claim(f.r, claim.Identity, f.c, local, f.now.Add(-time.Second))
			if err != nil {
				t.Fatal("manager double claim")
			}
			if f.lostClaim {
				return nil, 0, ErrTransport
			}
			grant, _ := windowseventwire.GrantFor(f.r)
			b, _ := windowseventwire.EncodeGrant(grant)
			return b, http.StatusOK, nil
		case windowseventwire.ResultPath:
			f.results = append(f.results, bytes.Clone(body))
			if f.lostResult {
				f.lostResult = false
				return nil, 0, ErrTransport
			}
			result, e := windowseventwire.DecodeResult(body)
			if e != nil {
				t.Fatal(e)
			}
			accepted, e := windowseventrequest.Accept(f.r, result.Claim.Identity, f.c, local, result.Report, f.now)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := windowseventwire.EncodeReceipt(*accepted.Receipt)
			return b, http.StatusOK, nil
		case windowseventwire.StatusPath:
			if _, e := windowseventwire.DecodeStatusInput(body); e != nil {
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
func TestWindowsEventContentPipelineExactRetryAndNoDurableContent(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := eventFixtureFor(t, profile)
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
func TestWindowsEventContentNoGrantAndDisableNeverRead(t *testing.T) {
	for _, mode := range []string{"missing", "denied", "disabled", "replaced"} {
		f := eventFixtureFor(t, "http-test")
		switch mode {
		case "missing":
			f.localErr = errEventContentDisabled
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
func TestWindowsEventContentLostClaimAndRestartNeverCapture(t *testing.T) {
	f := eventFixtureFor(t, "http-test")
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
	f = eventFixtureFor(t, "tls")
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
func TestWindowsEventContentCapabilityLostReplyRetriesExactBytes(t *testing.T) {
	f := eventFixtureFor(t, "tls")
	f.lostCapability = true
	if f.s.Run(context.Background()) != "unavailable" || f.captures != 0 {
		t.Fatal("capability failure captured")
	}
	f.now = f.now.Add(time.Second)
	if f.s.Run(context.Background()) != "acknowledged" {
		t.Fatal("retry failed")
	}
	if len(f.capabilities) != 2 || !bytes.Equal(f.capabilities[0], f.capabilities[1]) {
		t.Fatal("capability metadata refreshed")
	}
}
func TestWindowsEventContentRevocationAndExpiryErasePending(t *testing.T) {
	for _, mode := range []string{"disable", "replace", "expired", "backwards", "identity"} {
		f := eventFixtureFor(t, "tls")
		f.lostResult = true
		if f.s.Run(context.Background()) != "pending_retained" {
			t.Fatal("no retained content")
		}
		held := f.s.pending.memory
		switch mode {
		case "disable":
			f.c.Enabled = false
		case "replace":
			f.c.GrantID = strings.Repeat("8", 32)
		case "expired":
			f.now = f.r.Description.ExpiresAt
		case "backwards":
			f.now = f.r.Description.CreatedAt.Add(-time.Second)
		case "identity":
			f.localErr = ErrState
		}
		f.s.prune()
		held.mu.Lock()
		exists := len(held.raw) > 0
		held.mu.Unlock()
		if exists || f.s.pending != nil {
			t.Fatal(mode, "retained revoked content")
		}
		if len(f.results) != 1 {
			t.Fatal("unexpected retransmit")
		}
	}
}
func TestWindowsEventContentStorageFailuresPreventCapture(t *testing.T) {
	for _, file := range []string{"reports.json", "consumed.json"} {
		f := eventFixtureFor(t, "tls")
		delete(f.memory.values, file)
		f.s.Run(context.Background())
		if f.captures != 0 {
			t.Fatal("missing used state captured", file)
		}
	}
	f := eventFixtureFor(t, "tls")
	f.memory.fail = true
	f.s.Run(context.Background())
	if f.captures != 0 || f.claims != 0 {
		t.Fatal("ambiguous storage reached native")
	}
}
func TestWindowsEventContentPartialReportErrorSurvives(t *testing.T) {
	f := eventFixtureFor(t, "tls")
	collect := f.s.collect
	f.s.collect = func(ctx context.Context, r windowseventworker.Request) (windowseventcontent.Report, error) {
		out, e := collect(ctx, r)
		if e != nil {
			return out, e
		}
		out.Complete = false
		out.Quality = windowseventcontent.QualityUnavailable
		out.Events[0].Message = ""
		out.Events[0].Complete = false
		out.Events[0].Quality = windowseventcontent.QualityUnavailable
		out.Events[0].Reason = windowseventcontent.ErrNotFound.Error()
		return out, errors.New("synthetic raw error must not escape")
	}
	if got := f.s.Run(context.Background()); got != "acknowledged" {
		t.Fatal("valid unavailable report was lost", got)
	}
}

func TestWindowsEventContentTerminalRejectionErasesPending(t *testing.T) {
	for _, path := range []string{windowseventwire.CapabilityPath, windowseventwire.ResultPath} {
		for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusGone} {
			f := eventFixtureFor(t, "tls")
			f.lostResult = true
			if f.s.Run(context.Background()) != "pending_retained" {
				t.Fatal("pending result absent")
			}
			held := f.s.pending.memory
			exchange := f.s.exchange
			f.s.exchange = func(ctx context.Context, p string, seq uint64, b []byte) ([]byte, int, error) {
				if p == path {
					return []byte("{}"), code, nil
				}
				return exchange(ctx, p, seq, b)
			}
			f.s.Run(context.Background())
			held.mu.Lock()
			has := len(held.raw) > 0
			held.mu.Unlock()
			if has || f.s.pending != nil || f.captures != 1 || f.claims != 1 {
				t.Fatal("terminal rejection retained or recaptured", path, code)
			}
		}
	}
}

func TestWindowsEventContentCapabilityAuthorityRaceErasesPending(t *testing.T) {
	f := eventFixtureFor(t, "tls")
	f.lostResult = true
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("pending result absent")
	}
	held := f.s.pending.memory
	checks := 0
	f.s.local = func(Material) (windowseventrequest.Consent, error) {
		checks++
		if checks >= 3 {
			return windowseventrequest.Consent{}, ErrState
		}
		return f.c, nil
	}
	f.s.Run(context.Background())
	held.mu.Lock()
	has := len(held.raw) > 0
	held.mu.Unlock()
	if has || f.s.pending != nil || f.captures != 1 || len(f.results) != 1 {
		t.Fatal("changed capability authority retained content")
	}
}

func TestWindowsEventContentSerializedSenderProofAndTLSSeams(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := eventFixtureFor(t, profile)
			f.lostResult = true
			original := f.s.exchange
			var verifier *windowseventwire.Verifier
			var err error
			m := f.s.material
			transport := newHTTPClient(m.tlsConfig, profile == "http-test")
			defer transport.CloseIdleConnections()
			native := transport.Transport.(*http.Transport)
			if native.Proxy != nil || !native.DisableCompression || native.TLSClientConfig != m.tlsConfig || transport.CheckRedirect == nil {
				t.Fatal("unsafe transport defaults")
			}
			if profile == "http-test" {
				verifier, err = windowseventwire.New(windowseventwire.Config{Origin: m.config.ManagerOrigin, Registry: windowsPublicFixture{m.certificate.Certificate[0], m.config.AgentID}, Now: func() time.Time { return f.now }})
				if err != nil {
					t.Fatal(err)
				}
			}
			f.s.client = &http.Client{Transport: setupRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				var raw []byte
				var sequence uint64
				if verifier != nil {
					v, e := verifier.Verify(req)
					if e != nil {
						t.Fatal("proof failed", e)
					}
					raw, sequence = v.Body, v.Sequence
				} else {
					cert, e := x509.ParseCertificate(m.certificate.Certificate[0])
					if e != nil {
						t.Fatal(e)
					}
					req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
					if windowseventwire.ValidateShape(req, req.URL.Host, "tls") != nil {
						t.Fatal("TLS shape rejected")
					}
					raw, _ = io.ReadAll(req.Body)
					sequence = f.r.Description.Identity.Sequence
					if req.URL.Path == windowseventwire.PeekPath {
						sequence = 1
					}
					if req.URL.Path == windowseventwire.CapabilityPath {
						cap, e := windowseventwire.DecodeCapability(raw)
						if e != nil {
							t.Fatal(e)
						}
						sequence = cap.Sequence
					}
				}
				body, code, e := original(req.Context(), req.URL.Path, sequence, raw)
				if e != nil {
					return nil, e
				}
				return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			f.s.exchange = f.s.request
			if got := f.s.Run(context.Background()); got != "pending_retained" {
				t.Fatal(got)
			}
			f.now = f.now.Add(time.Second)
			if got := f.s.Run(context.Background()); got != "acknowledged" {
				t.Fatal(got)
			}
			if f.captures != 1 || f.claims != 1 || len(f.results) != 2 || !bytes.Equal(f.results[0], f.results[1]) {
				t.Fatal("serialized sender changed exact retry")
			}
		})
	}
}
func TestWindowsEventContentMalformedTerminalResponseStillPurges(t *testing.T) {
	f := eventFixtureFor(t, "tls")
	f.lostResult = true
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("missing pending")
	}
	held := f.s.pending.memory
	f.s.client = &http.Client{Transport: setupRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"Content-Type": []string{"text/html"}, "Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(strings.NewReader("untrusted error page"))}, nil
	})}
	f.s.exchange = f.s.request
	if got := f.s.Run(context.Background()); got != "denied" {
		t.Fatal(got)
	}
	held.mu.Lock()
	retained := len(held.raw) > 0
	held.mu.Unlock()
	if retained || f.s.pending != nil {
		t.Fatal("error page prevented purge")
	}
}
func TestWindowsEventContentTimerClearsUnsentContent(t *testing.T) {
	p := &windowsEventContentPending{memory: &journalMemory{raw: []byte("synthetic")}, done: make(chan struct{}), grant: windowseventwire.Grant{Description: windowseventrequest.Description{ExpiresAt: time.Now().Add(10 * time.Millisecond)}}}
	p.startExpiry()
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("expiry callback missing")
	}
	p.memory.mu.Lock()
	retained := len(p.memory.raw) > 0
	expired := p.memory.expired
	p.memory.mu.Unlock()
	if retained || !expired {
		t.Fatal("expiry retained content")
	}
	s := &windowsEventContentSender{pending: p}
	s.discard()
}
