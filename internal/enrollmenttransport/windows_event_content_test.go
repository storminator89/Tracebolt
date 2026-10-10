package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalwire"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type eventTransportFixture struct {
	f          *fixture
	h          *Ingress
	origin     string
	client     *http.Client
	cache      *windowseventcache.Cache
	clock      atomic.Int64
	active     atomic.Bool
	owner      windowseventcache.Owner
	cancel     context.CancelFunc
	capability windowseventwire.Capability
	headers    windowseventhealth.Snapshot
}

func (x *eventTransportFixture) now() time.Time { return time.Unix(0, x.clock.Load()).UTC() }
func (x *eventTransportFixture) request(t *testing.T, path string, sequence uint64, body []byte) *http.Request {
	t.Helper()
	if x.f.config.Binding.Profile == "http-test" {
		req, e := windowseventwire.NewSignedRequest(context.Background(), x.origin, path, x.f.pair, sequence, time.Now().UTC(), body)
		if e != nil {
			t.Fatal(e)
		}
		return req
	}
	req, e := http.NewRequest(http.MethodPost, x.origin+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
func newEventTransportFixture(t *testing.T, profile string, wrap func(http.Handler) http.Handler) *eventTransportFixture {
	t.Helper()
	f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
	if e := f.store.InitializeWindowsEventContent(context.Background()); e != nil {
		t.Fatal(e)
	}
	h, server, client := f.listen(t, wrap)
	x := &eventTransportFixture{f: f, h: h, origin: server.URL, client: client}
	x.clock.Store(f.now.Add(2 * time.Second).UnixNano())
	x.active.Store(true)
	h.now = x.now
	x.cache = windowseventcache.New(f.store, x.now)
	t.Cleanup(x.cache.Close)
	if e := h.ConfigureWindowsEventContent(x.cache); e != nil {
		t.Fatal(e)
	}
	life, cancel := context.WithCancel(context.Background())
	x.cancel = cancel
	t.Cleanup(cancel)
	x.owner = windowseventcache.Owner{ID: "synthetic-authenticated-owner-session", ExpiresAt: x.now().Add(time.Hour), Lifetime: life, Active: x.active.Load}
	consent := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: profile, Enabled: true, ContentAcknowledged: true, HTTPPlaintextAcknowledged: profile == "http-test"}
	cap, e := windowseventwire.CapabilityFor(consent, windowseventrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: profile, DeviceID: f.snapshot.Approval.DeviceID, CertificateHash: f.cert.CertificateHash()}, 1, x.now())
	if e != nil {
		t.Fatal(e)
	}
	x.capability = cap
	body, e := windowseventwire.EncodeCapability(cap)
	if e != nil {
		t.Fatal(e)
	}
	got := response(t, client, x.request(t, windowseventwire.CapabilityPath, 1, body), 200)
	if !bytes.Equal(got, body) {
		t.Fatal("capability receipt changed exact original metadata")
	}
	x.headers = windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("c", 32), GenerationID: id("sample", 1), CollectedAt: x.now(), Channels: []windowseventhealth.Channel{
		{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 2, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 14, Level: 2, Provider: "Synthetic publisher", Timestamp: x.now().Add(-time.Second).Add(123456700 * time.Nanosecond)}, {RecordID: "9007199254740993", EventID: 15, Level: 3, Provider: "Synthetic publisher", Timestamp: x.now().Add(-2 * time.Second)}}},
		{Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}},
	}}
	x.saveHeaders(t, 1, x.headers)
	return x
}

// A direct fixture-only insertion establishes an accepted frame without invoking
// any native collector. Actual capability/peek/claim/result/status use listeners.
func (x *eventTransportFixture) saveHeaders(t *testing.T, sequence uint64, headers windowseventhealth.Snapshot) {
	t.Helper()
	at := headers.CollectedAt
	value := 42.0
	metric := model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Synthetic measured fixture", CollectedAt: at}
	report := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Windows fixture", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Fixture", Scope: "Explicit hostname scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "fixture-windows"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Fixture", Scope: "Bounded process scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 12, Name: "fixture.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Fixture", Scope: "Denied service scope", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Fixture", Scope: "Partial software scope", Quality: "limited", Rows: []windowsinventory.Software{{Name: "Fixture app", Version: "1", Publisher: "Fixture", RegistryView: "64"}}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Fixture", Scope: "Explicit interface scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 1, Name: "Fixture", Address: "192.0.2.8", PrefixLength: 24}}},
	}
	snap, device, e := windowsmanaged.FromReport(report, id("sample", int(sequence)))
	if e != nil {
		t.Fatal(e)
	}
	observation := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}
	raw, e := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameWindowsEventsVersion, Sequence: sequence, Observation: observation, WindowsInventory: &snap, WindowsEvents: &headers})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.f.store.SaveObservation(context.Background(), x.f.snapshot.InvitationID, x.f.cert.CertificateHash(), raw, x.now()); e != nil {
		t.Fatal(e)
	}
}
func (x *eventTransportFixture) create(t *testing.T) windowseventrequest.Description {
	t.Helper()
	raw := response(t, x.client, x.request(t, windowseventwire.PeekPath, 1, []byte("{}")), 200)
	if string(raw) != "null" {
		t.Fatal("empty peek not explicit null")
	}
	status, e := x.f.store.WindowsEventContentStatus(context.Background(), x.f.snapshot.Approval.DeviceID, x.now())
	if e != nil || status.Headers == nil {
		t.Fatal("missing accepted headers", e)
	}
	d, e := x.cache.Create(context.Background(), x.f.snapshot.Approval.DeviceID, x.owner, 0, status.Headers.GenerationID, status.Headers.SnapshotDigest, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}, {Channel: "Application", RecordID: "9007199254740993"}}, x.now())
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func (x *eventTransportFixture) claim(t *testing.T, d windowseventrequest.Description) windowseventwire.Grant {
	t.Helper()
	raw := response(t, x.client, x.request(t, windowseventwire.PeekPath, 1, []byte("{}")), 200)
	peek, e := windowseventwire.DecodeDescription(raw)
	if e != nil || !reflect.DeepEqual(peek, d) {
		t.Fatal("peek altered exact original description", e)
	}
	claim, e := windowseventwire.ClaimFor(d, x.capability.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	body, e := windowseventwire.EncodeClaim(claim)
	if e != nil {
		t.Fatal(e)
	}
	raw = response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body), 200)
	grant, e := windowseventwire.DecodeGrant(raw)
	if e != nil || !reflect.DeepEqual(grant.Description, d) || grant.PolicyDigest != claim.PolicyDigest {
		t.Fatal("claim grant changed authority", e)
	}
	response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body), 409)
	if raw = response(t, x.client, x.request(t, windowseventwire.PeekPath, 1, []byte("{}")), 200); string(raw) != "null" {
		t.Fatal("claimed work redisclosed as pending")
	}
	return grant
}
func partialEventTransportResult(t *testing.T, g windowseventwire.Grant, at time.Time) windowseventwire.Result {
	t.Helper()
	claim, e := windowseventwire.ClaimFor(g.Description, g.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	report := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: windowseventcontent.QualityPartial, CollectedAt: at, Events: []windowseventcontent.Result{
		{Event: g.Description.Query.Events[0], Message: "SYNTHETIC_PRIVATE_EVENT_CONTENT_NEVER_DURABLE", Quality: windowseventcontent.QualityObserved, Complete: true},
		{Event: g.Description.Query.Events[1], Quality: windowseventcontent.QualityUnavailable, Reason: windowseventcontent.ErrNotFound.Error()},
	}}
	out := windowseventwire.Result{Claim: claim, Report: report}
	if windowseventwire.ValidateResultForGrant(out, g) != nil {
		t.Fatal("invalid partial fixture")
	}
	return out
}
func TestWindowsEventRealTransportPartialRetryImmutableHeaders(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			x := newEventTransportFixture(t, profile, nil)
			d := x.create(t)
			replacement := x.headers
			replacement.GenerationID = id("sample", 2)
			replacement.CollectedAt = x.now().Add(time.Millisecond)
			replacement.Channels = append([]windowseventhealth.Channel(nil), x.headers.Channels...)
			replacement.Channels[0].Rows = append([]windowseventhealth.Event(nil), x.headers.Channels[0].Rows...)
			replacement.Channels[0].Rows[0].RecordID = "7"
			replacement.Channels[0].Rows[0].Provider = "New synthetic publisher"
			x.clock.Store(replacement.CollectedAt.UnixNano())
			x.saveHeaders(t, 2, replacement)
			grant := x.claim(t, d)
			if grant.Description.Query.Events[0].RecordID != math.MaxUint64 || grant.Description.HeaderGenerationID != x.headers.GenerationID {
				t.Fatal("replacement frame retargeted original request")
			}
			result := partialEventTransportResult(t, grant, x.now())
			body, e := windowseventwire.EncodeResult(result)
			if e != nil {
				t.Fatal(e)
			}
			accepted := response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 200)
			receipt, e := windowseventwire.DecodeReceipt(accepted)
			if e != nil || receipt.Identity != d.Identity || receipt.ExpiresAt != d.ExpiresAt {
				t.Fatal("invalid digest receipt", e)
			}
			digest, e := windowseventwire.ReportDigest(result.Report, d.Query)
			if e != nil || digest != receipt.ResultDigest {
				t.Fatal("native report digest changed")
			}
			retry := response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 200)
			if !bytes.Equal(retry, accepted) {
				t.Fatal("retry refreshed receipt")
			}
			page, e := x.cache.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now())
			if e != nil || page.Report.Quality != windowseventcontent.QualityPartial || len(page.Report.Events) != 2 || page.Report.Events[0].Event.RecordID != "18446744073709551615" || page.Report.Events[1].Reason != windowseventcontent.ErrNotFound.Error() || page.Report.Events[0].Message != result.Report.Events[0].Message {
				t.Fatal("partial browser cache lost identity/content", e)
			}
			if page.Report.Events[0].Event.Timestamp != d.Query.Events[0].Timestamp || page.ExpiresAt != d.ExpiresAt {
				t.Fatal("precision/original expiry changed")
			}
			foreignOwner := x.owner
			foreignOwner.ID = "another-owner-session"
			if _, e = x.cache.Query(context.Background(), d.DeviceID, foreignOwner, d.Identity, x.now()); e == nil {
				t.Fatal("foreign session read content")
			}
			changed := result
			changed.Report.Events = append([]windowseventcontent.Result(nil), result.Report.Events...)
			changed.Report.Events[0].Message = "different synthetic content"
			different, _ := windowseventwire.EncodeResult(changed)
			response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, different), 409)
			for _, path := range []string{x.f.path, x.f.path + "-wal"} {
				b, e := os.ReadFile(path)
				if e != nil && !os.IsNotExist(e) {
					t.Fatal(e)
				}
				if bytes.Contains(b, []byte(result.Report.Events[0].Message)) {
					t.Fatal("message content persisted")
				}
			}
			status, _ := windowseventwire.EncodeStatus(windowseventwire.StatusInput{Claim: result.Claim, LocalStatus: "checking"})
			if got := response(t, x.client, x.request(t, windowseventwire.StatusPath, d.Identity.Sequence, status), 200); string(got) != "{}" {
				t.Fatal("status ack shape")
			}
			x.cache.Close()
			// Exact retained-byte retry remains receipt-only after cache loss.
			restarted := windowseventcache.New(x.f.store, x.now)
			t.Cleanup(restarted.Close)
			again, e := restarted.Accept(context.Background(), d.DeviceID, d.CertificateHash, result, x.now())
			if e != nil || again != receipt {
				t.Fatal("digest-only retry failed", e)
			}
			if _, e = restarted.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now()); e == nil {
				t.Fatal("retry rehydrated lost cache")
			}
			response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 200)
			if _, e = x.cache.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now()); e == nil {
				t.Fatal("network retry rehydrated cache")
			}
			claimBytes, _ := windowseventwire.EncodeClaim(result.Claim)
			response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, claimBytes), 409)
			x.revoke(t)
			response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 403)
		})
	}
}

func TestWindowsEventRealTransportPurposeSequenceProfileAndForeignCertificate(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			x := newEventTransportFixture(t, profile, nil)
			response(t, x.client, x.request(t, windowseventwire.PeekPath, 1, []byte(`{"unexpected":true}`)), 400)
			if profile == "http-test" {
				response(t, x.client, x.request(t, windowseventwire.PeekPath, 2, []byte("{}")), 400)
				capBody, _ := windowseventwire.EncodeCapability(x.capability)
				response(t, x.client, x.request(t, windowseventwire.CapabilityPath, 2, capBody), 400)
				old, e := journalwire.NewSignedRequest(context.Background(), x.origin, journalwire.PeekPath, x.f.pair, 1, time.Now().UTC(), []byte("{}"))
				if e != nil {
					t.Fatal(e)
				}
				for _, keys := range [][2]string{{journalwire.CertificateHeader, windowseventwire.CertificateHeader}, {journalwire.SequenceHeader, windowseventwire.SequenceHeader}, {journalwire.SignedAtHeader, windowseventwire.SignedAtHeader}, {journalwire.SignatureHeader, windowseventwire.SignatureHeader}} {
					old.Header.Set(keys[1], old.Header.Get(keys[0]))
					old.Header.Del(keys[0])
				}
				old.URL.Path = windowseventwire.PeekPath
				response(t, x.client, old, 403)
			} else {
				req := x.request(t, windowseventwire.PeekPath, 1, []byte("{}"))
				req.Header.Set(windowseventwire.SignatureHeader, "not-a-tls-fallback")
				response(t, x.client, req, 400)
			}
			profileSubstitution := x.capability
			profileSubstitution.Sequence++
			if profile == "tls" {
				profileSubstitution.Consent.Profile = "http-test"
				profileSubstitution.Consent.HTTPPlaintextAcknowledged = true
			} else {
				profileSubstitution.Consent.Profile = "tls"
				profileSubstitution.Consent.HTTPPlaintextAcknowledged = false
			}
			profileSubstitution.PolicyDigest, _ = windowseventwire.PolicyDigest(profileSubstitution.Consent)
			body, e := windowseventwire.EncodeCapability(profileSubstitution)
			if e != nil {
				t.Fatal(e)
			}
			response(t, x.client, x.request(t, windowseventwire.CapabilityPath, profileSubstitution.Sequence, body), 403)
			foreignBinding := x.capability
			foreignBinding.DeviceID = id("agent", 99)
			body, _ = windowseventwire.EncodeCapability(foreignBinding)
			response(t, x.client, x.request(t, windowseventwire.CapabilityPath, 1, body), 400)
			foreignBinding = x.capability
			foreignBinding.CertificateHash = strings.Repeat("f", 64)
			body, _ = windowseventwire.EncodeCapability(foreignBinding)
			response(t, x.client, x.request(t, windowseventwire.CapabilityPath, 1, body), 400)
			foreign := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
			if profile == "http-test" {
				req, e := windowseventwire.NewSignedRequest(context.Background(), x.origin, windowseventwire.PeekPath, foreign.pair, 1, time.Now().UTC(), []byte("{}"))
				if e != nil {
					t.Fatal(e)
				}
				response(t, x.client, req, 403)
			} else {
				transport := x.client.Transport.(*http.Transport).Clone()
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
				transport.TLSClientConfig.Certificates = []tls.Certificate{foreign.pair}
				t.Cleanup(transport.CloseIdleConnections)
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				req := x.request(t, windowseventwire.PeekPath, 1, []byte("{}"))
				res, e := client.Do(req)
				if e == nil {
					defer res.Body.Close()
					if res.StatusCode < 400 {
						t.Fatal("foreign TLS issuer authenticated")
					}
				}
			}
			unattached, e := New(x.f.store, x.f.issuer.IssuerDER(), x.origin)
			if e != nil {
				t.Fatal(e)
			}
			otherCache := windowseventcache.New(foreign.store, time.Now)
			t.Cleanup(otherCache.Close)
			if unattached.ConfigureWindowsEventContent(otherCache) == nil {
				t.Fatal("cache from another authority attached")
			}
			stale := x.capability
			stale.Sequence++
			stale.CollectedAt = x.now().Add(-windowseventwire.CapabilityMaxAge)
			staleBody, _ := windowseventwire.EncodeCapability(stale)
			response(t, x.client, x.request(t, windowseventwire.CapabilityPath, stale.Sequence, staleBody), 400)
			d := x.create(t)
			claim, _ := windowseventwire.ClaimFor(d, x.capability.PolicyDigest)
			claim.CertificateHash = strings.Repeat("e", 64)
			body, _ = windowseventwire.EncodeClaim(claim)
			response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body), 409)
			disabled := x.capability
			disabled.Sequence++
			disabled.Consent.Enabled = false
			disabled.PolicyDigest, _ = windowseventwire.PolicyDigest(disabled.Consent)
			body, _ = windowseventwire.EncodeCapability(disabled)
			response(t, x.client, x.request(t, windowseventwire.CapabilityPath, disabled.Sequence, body), 200)
			claim, _ = windowseventwire.ClaimFor(d, x.capability.PolicyDigest)
			body, _ = windowseventwire.EncodeClaim(claim)
			response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body), 409)
		})
	}
	// Existing Linux collection identities cannot gain Windows scope by reaching
	// the route or attaching an otherwise matching ephemeral cache.
	for _, profile := range []string{"tls", "http-test"} {
		t.Run("linux-"+profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			h, server, client := f.listen(t, nil)
			cache := windowseventcache.New(f.store, time.Now)
			t.Cleanup(cache.Close)
			if h.ConfigureWindowsEventContent(cache) == nil {
				t.Fatal("Linux profile adopted event scope")
			}
			x := &eventTransportFixture{f: f, origin: server.URL, client: client}
			response(t, client, x.request(t, windowseventwire.PeekPath, 1, []byte("{}")), 404)
		})
	}
}

type eventHTTPOutcome struct {
	code int
	raw  []byte
	err  error
}

func eventAsyncRequest(client *http.Client, req *http.Request) <-chan eventHTTPOutcome {
	done := make(chan eventHTTPOutcome, 1)
	go func() {
		res, e := client.Do(req)
		if e != nil {
			done <- eventHTTPOutcome{err: e}
			return
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, windowseventwire.MaxMetadataBytes+1))
		done <- eventHTTPOutcome{code: res.StatusCode, raw: raw, err: e}
	}()
	return done
}
func TestWindowsEventRealTransportBodyDelayRechecksOwnerRevocationAndExpiry(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, change := range []string{"logout", "revoked", "expired"} {
			t.Run(profile+"/"+change, func(t *testing.T) {
				entered, proceed := make(chan struct{}), make(chan struct{})
				var once sync.Once
				release := func() { once.Do(func() { close(proceed) }) }
				defer release()
				x := newEventTransportFixture(t, profile, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == windowseventwire.ClaimPath {
							r.Body = &journalGatedBody{ReadCloser: r.Body, entered: entered, proceed: proceed}
						}
						next.ServeHTTP(w, r)
					})
				})
				d := x.create(t)
				claim, _ := windowseventwire.ClaimFor(d, x.capability.PolicyDigest)
				body, _ := windowseventwire.EncodeClaim(claim)
				done := eventAsyncRequest(x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body))
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					release()
					t.Fatal("body gate not reached")
				}
				switch change {
				case "logout":
					x.active.Store(false)
					x.cancel()
				case "revoked":
					x.revoke(t)
				case "expired":
					x.clock.Store(d.ExpiresAt.UnixNano())
				}
				release()
				select {
				case got := <-done:
					if got.err != nil || (got.code != 403 && got.code != 409) || bytes.Contains(got.raw, []byte("claimedAt")) || bytes.Contains(got.raw, []byte("Synthetic publisher")) {
						t.Fatal("delayed request crossed authority boundary", got.code, got.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("gated request did not finish")
				}
				// No result exists to disclose after any lost authority.
				if _, e := x.cache.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now()); e == nil {
					t.Fatal("lost authority retained content")
				}
			})
		}
	}
}
func TestWindowsEventRealTransportFinalExpirySuppressesCommittedClaim(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			x := newEventTransportFixture(t, profile, nil)
			var armed atomic.Bool
			var ownerChecks atomic.Int32
			base := x.now()
			// Claim checks ownership once before its durable commit. AuthorizeReply
			// checks it twice more. Cross original expiry at the final owner check,
			// after the reply was encoded and its authority transaction completed.
			x.owner.Active = func() bool {
				if armed.Load() && ownerChecks.Add(1) == 3 {
					x.clock.Store(base.Add(windowseventrequest.Lifetime).UnixNano())
				}
				return true
			}
			d := x.create(t)
			armed.Store(true)
			claim, _ := windowseventwire.ClaimFor(d, x.capability.PolicyDigest)
			body, _ := windowseventwire.EncodeClaim(claim)
			raw := response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, body), 409)
			if ownerChecks.Load() != 3 || bytes.Contains(raw, []byte("claimedAt")) || bytes.Contains(raw, []byte("Synthetic publisher")) {
				t.Fatal("final expiry disclosure check not exercised")
			}
			// No clock rollback or hidden second claim is needed to inspect persistence:
			// the last durable transaction still used base time, before final disclosure.
			status, e := x.f.store.WindowsEventContentStatus(context.Background(), d.DeviceID, base)
			if e != nil || status.Request == nil || status.Request.State != windowseventrequest.Claimed || status.Request.Description.Identity != d.Identity {
				t.Fatal("lost grant response did not retain one-use claim", e)
			}
		})
	}
}

func (x *eventTransportFixture) revoke(t *testing.T) {
	t.Helper()
	other, e := enrollmentstore.Open(x.f.path, x.f.config, x.f.issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	control := x.f.control(30)
	control.Now = x.now().Unix()
	x.f.snapshot, e = other.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked})
	if e != nil {
		t.Fatal(e)
	}
}

func TestWindowsEventRealTransportLogoutDiscardsAcceptedContent(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			x := newEventTransportFixture(t, profile, nil)
			d := x.create(t)
			grant := x.claim(t, d)
			result := partialEventTransportResult(t, grant, x.now())
			body, e := windowseventwire.EncodeResult(result)
			if e != nil {
				t.Fatal(e)
			}
			response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 200)
			if _, e = x.cache.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now()); e != nil {
				t.Fatal("fixture never exposed authorized content", e)
			}
			x.active.Store(false)
			x.cancel()
			if _, e = x.cache.Query(context.Background(), d.DeviceID, x.owner, d.Identity, x.now()); e == nil {
				t.Fatal("logout retained accepted content")
			}
			response(t, x.client, x.request(t, windowseventwire.ResultPath, d.Identity.Sequence, body), 409)
			claim, _ := windowseventwire.EncodeClaim(result.Claim)
			response(t, x.client, x.request(t, windowseventwire.ClaimPath, d.Identity.Sequence, claim), 409)
			status, e := x.f.store.WindowsEventContentStatus(context.Background(), d.DeviceID, x.now())
			if e != nil || status.Request == nil || status.Request.State != windowseventrequest.Canceled {
				t.Fatal("logout did not preserve terminal authority", e)
			}
		})
	}
}
