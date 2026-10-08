//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func serviceStartupConsentFixture(m Material) windowsmanaged.ServiceStartupConsent {
	return windowsmanaged.ServiceStartupConsent{SchemaVersion: windowsmanaged.ServiceStartupConsentVersion, Scope: windowsmanaged.ServiceStartupScope, SenderBinding: m.binding, GrantID: strings.Repeat("f", 32), Enabled: true}
}
func startupWindowsSource(_ context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
	r := syntheticWindowsReport(time.Now().UTC())
	r.Services.Quality, r.Services.Complete = "healthy", true
	r.Services.Rows = []windowsinventory.Service{{Name: "InventedA", DisplayName: "Duplicate display", State: "running", PID: 7}, {Name: "InventedB", DisplayName: "Duplicate display", State: "stopped", PID: 0}}
	return windowsmanaged.FromReport(r, generation)
}
func serviceStartupSourceFixture(ctx context.Context, rows []windowsmanaged.Service, generation, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
	return windowsmanaged.CollectServiceStartupWithReader(ctx, rows, generation, grant, at, func(_ context.Context, name string) (windowsmanaged.ServiceStartupRow, error) {
		mode, delayed := "automatic", false
		if name == "InventedA" {
			mode = "disabled"
			return windowsmanaged.ServiceStartupRow{StartupMode: &mode, StartupQuality: "observed", DelayedAutoQuality: "not-applicable"}, nil
		}
		return windowsmanaged.ServiceStartupRow{StartupMode: &mode, StartupQuality: "observed", DelayedAutoStart: &delayed, DelayedAutoQuality: "observed"}, nil
	})
}

// Exercise the TLS ingress admission with a verified, in-memory fixture chain.
// This is not a real socket/TLS handshake or native Windows acceptance.
func startupServe(t *testing.T, f *windowsManagerFixture, req *http.Request) *http.Response {
	t.Helper()
	if f.config.Binding.Profile == "tls" {
		leaf, e := x509.ParseCertificate(f.material.certificate.Certificate[0])
		if e != nil {
			t.Fatal(e)
		}
		issuer, e := x509.ParseCertificate(f.issuer.IssuerDER())
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AddCert(issuer)
		chains, e := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now().UTC()})
		if e != nil {
			t.Fatal(e)
		}
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf, issuer}, VerifiedChains: chains}
	}
	return f.serve(t, req, http.StatusOK)
}

func TestWindowsServiceStartupAll32CombinationsBothTransportAdmissions(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for bits := 0; bits < 32; bits++ {
			t.Run(fmt.Sprintf("%s/%02d", transport, bits), func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				ec, vc, pc, nc, sc := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material)
				ec.Enabled, vc.Enabled, pc.Enabled, nc.Enabled, sc.Enabled = bits&1 != 0, bits&2 != 0, bits&4 != 0, bits&8 != 0, bits&16 != 0
				calls := 0
				var sent frame
				_, e = runUsingStateWithServiceStartupDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if e := json.Unmarshal(raw, &sent); e != nil {
						t.Fatal(e)
					}
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, ec.Enabled }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, vc.Enabled }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, pc.Enabled }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, nc.Enabled }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, sc.Enabled }, func(ctx context.Context, rows []windowsmanaged.Service, g, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
					calls++
					return serviceStartupSourceFixture(ctx, rows, g, grant, at)
				})
				if e != nil {
					t.Fatal(e)
				}
				v := f.view(t, time.Now().UTC())
				if (v.Events != nil) != ec.Enabled || (v.Volumes != nil) != vc.Enabled || (v.ProcessMetrics != nil) != pc.Enabled || (v.Network != nil) != nc.Enabled || (v.ServiceStartup != nil) != sc.Enabled {
					t.Fatal("independent scope selection changed")
				}
				want := FrameWindowsInventoryVersion
				if ec.Enabled {
					want = FrameWindowsEventsVersion
				}
				if vc.Enabled {
					want = FrameWindowsCapabilitiesVersion
				}
				if pc.Enabled {
					want = FrameWindowsProcessMetricsVersion
				}
				if nc.Enabled {
					want = FrameWindowsNetworkVersion
				}
				if sc.Enabled {
					want = FrameWindowsServiceStartupVersion
				}
				if sent.SchemaVersion != want || calls != bits>>4 {
					t.Fatal("default-off/version behavior changed", sent.SchemaVersion, want, calls)
				}
				if sc.Enabled {
					digest, _ := windowsmanaged.ServiceStartupRowsSHA256(v.Snapshot.Services.Rows)
					if v.ServiceStartup.ServicesSHA256 != digest || len(v.ServiceStartup.Rows) != 2 || *v.ServiceStartup.Rows[0].StartupMode != "disabled" || v.Snapshot.Services.Rows[0].State != "running" {
						t.Fatal("startup metadata changed service state or row association")
					}
				}
				basic, e := f.store.LatestObservations(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(basic)
				if bytes.Contains(raw, []byte("serviceStartup")) || bytes.Contains(raw, []byte("startupMode")) || bytes.Contains(raw, []byte("InventedA")) {
					t.Fatal("private startup data leaked to basic observation")
				}
			})
		}
	}
}

func TestWindowsServiceStartupSenderRetryRestartDenialAndIndependentDisable(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { state.Close() }()
			sc, nc := serviceStartupConsentFixture(f.material), networkConsentFixture(f.material)
			calls := 0
			denied := false
			var bodies [][]byte
			var receipts []lanstore.Receipt
			run := func() (Report, error) {
				return runUsingStateWithServiceStartupDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					b, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(b))
					bodies = append(bodies, bytes.Clone(b))
					resp := startupServe(t, f, req)
					raw, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var receipt lanstore.Receipt
					json.Unmarshal(raw, &receipt)
					receipts = append(receipts, receipt)
					if len(bodies) == 1 {
						return nil, errors.New("synthetic response loss")
					}
					resp.Body = io.NopCloser(bytes.NewReader(raw))
					return resp, nil
				}, nil, nil, nil, nil, nil, nil, func() (windowsnetwork.Consent, bool) { return nc, nc.Enabled }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, sc.Enabled }, func(ctx context.Context, rows []windowsmanaged.Service, g, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
					calls++
					if denied {
						return windowsmanaged.CollectServiceStartupWithReader(ctx, rows, g, grant, at, func(context.Context, string) (windowsmanaged.ServiceStartupRow, error) {
							return windowsmanaged.ServiceStartupRow{}, windowsmanaged.ErrServiceStartupDenied
						})
					}
					return serviceStartupSourceFixture(ctx, rows, g, grant, at)
				})
			}
			if _, e = run(); !errors.Is(e, ErrTransport) {
				t.Fatal(e)
			}
			before := f.view(t, time.Now().UTC())
			if before.ServiceStartup == nil || before.Network == nil {
				t.Fatal("missing combined snapshot")
			}
			state.Close()
			f.store.Close()
			f.open(t)
			state, e = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			report, e := run()
			if e != nil || !report.Duplicate || calls != 1 || !bytes.Equal(bodies[0], bodies[1]) || !receipts[0].ReceivedAt.Equal(receipts[1].ReceivedAt) {
				t.Fatal("retry bytes/capture/receipt changed", e)
			}
			after := f.view(t, time.Now().UTC())
			if !after.ServiceStartup.CollectedAt.Equal(before.ServiceStartup.CollectedAt) {
				t.Fatal("restart refreshed capture")
			}
			if stale := f.view(t, time.Now().UTC().Add(3*time.Minute)); stale.Status != "stale" || stale.ServiceStartup == nil {
				t.Fatal("stale truth hidden")
			}
			if expired := f.view(t, time.Now().UTC().Add(25*time.Hour)); expired.ServiceStartup != nil {
				t.Fatal("expired private data retained")
			}
			denied = true
			if _, e = run(); e != nil {
				t.Fatal(e)
			}
			v := f.view(t, time.Now().UTC())
			if v.ServiceStartup == nil || len(v.ServiceStartup.Rows) != 2 || v.ServiceStartup.Rows[0].StartupQuality != "denied" || v.ServiceStartup.Rows[0].StartupMode != nil {
				t.Fatal("denial reused previous value")
			}
			sc.Enabled = false
			if _, e = run(); e != nil {
				t.Fatal(e)
			}
			v = f.view(t, time.Now().UTC())
			if v.ServiceStartup != nil || v.Network == nil || calls != 2 {
				t.Fatal("disable changed independent scope")
			}
			var sent frame
			json.Unmarshal(bodies[len(bodies)-1], &sent)
			if sent.SchemaVersion != FrameWindowsNetworkVersion {
				t.Fatal("v5 compatibility changed")
			}
		})
	}
}

func TestWindowsServiceStartupPendingRevocationReplacementAndRaces(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := serviceStartupConsentFixture(m)
	calls := 0
	var sent frame
	send := func(r *http.Request) (*http.Response, error) {
		calls++
		sent = frame{}
		json.NewDecoder(r.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}
	run := func(read func() (windowsmanaged.ServiceStartupConsent, bool), source serviceStartupCollector) (Report, error) {
		return runUsingStateWithServiceStartupDependencies(context.Background(), m, state, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, read, source)
	}
	read := func() (windowsmanaged.ServiceStartupConsent, bool) { return c, c.Enabled }
	run(read, serviceStartupSourceFixture)
	p, _ := state.Pending()
	if p == nil || sent.WindowsServiceStartup == nil {
		t.Fatal("no pending startup")
	}
	old := p.Sequence
	c.GrantID = strings.Repeat("c", 32)
	r, _ := run(read, serviceStartupSourceFixture)
	if !r.DiscardedUnconsented || sent.Sequence <= old || sent.WindowsServiceStartup.GrantID != c.GrantID {
		t.Fatal("replaced grant replayed")
	}
	c.Enabled = false
	r, _ = run(read, serviceStartupSourceFixture)
	if !r.DiscardedUnconsented || sent.WindowsServiceStartup != nil || sent.SchemaVersion != FrameWindowsInventoryVersion {
		t.Fatal("revoked pending transmitted")
	}
	p, _ = state.Pending()
	state.Discard(p.Digest)
	c.Enabled = true
	_, e = run(read, func(ctx context.Context, rows []windowsmanaged.Service, g, grant string, at time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		s, e := serviceStartupSourceFixture(ctx, rows, g, grant, at)
		c.Enabled = false
		return s, e
	})
	if e == nil || calls != 3 {
		t.Fatal("revoked capture sent")
	}
	c.Enabled = true
	reads := 0
	_, e = run(func() (windowsmanaged.ServiceStartupConsent, bool) { reads++; return c, reads < 4 }, serviceStartupSourceFixture)
	if !errors.Is(e, ErrState) || calls != 3 || reads != 4 {
		t.Fatal("presend revocation ignored", e, reads, calls)
	}
	p, _ = state.Pending()
	if p == nil {
		t.Fatal("sequence reservation reset")
	}
	c.Enabled = false
	r, _ = run(read, serviceStartupSourceFixture)
	if !r.DiscardedUnconsented || sent.Sequence <= p.Sequence || sent.WindowsServiceStartup != nil {
		t.Fatal("revoked staged bytes not discarded on next attempt")
	}
}

func TestWindowsServiceStartupIngressStrictBindingsAndOldVersions(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	f, _, e := collectWindowsFrame(context.Background(), m.config, 1, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	f, raw, e := appendWindowsServiceStartup(context.Background(), m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := lanstore.ValidateFrame(raw, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileComplete} {
		if lanstore.FrameMatchesCollectionProfile(parsed, profile) {
			t.Fatal("profile confusion")
		}
	}
	changes := map[string]func(*frame){
		"scope":           func(f *frame) { f.WindowsServiceStartup.Scope = windowsmanaged.CollectionProfile },
		"generation":      func(f *frame) { f.WindowsServiceStartup.GenerationID = "sample_" + strings.Repeat("a", 32) },
		"grant":           func(f *frame) { f.WindowsServiceStartup.GrantID = "" },
		"digest":          func(f *frame) { f.WindowsServiceStartup.ServicesSHA256 = strings.Repeat("a", 64) },
		"reordered-base":  func(f *frame) { r := f.WindowsInventory.Services.Rows; r[0], r[1] = r[1], r[0] },
		"renamed-base":    func(f *frame) { f.WindowsInventory.Services.Rows[0].Name = "Changed" },
		"count":           func(f *frame) { f.WindowsServiceStartup.RequestedCount++ },
		"index":           func(f *frame) { f.WindowsServiceStartup.Rows[1].ServiceIndex = 2 },
		"duplicate-index": func(f *frame) { f.WindowsServiceStartup.Rows[1].ServiceIndex = 0 },
		"before-base": func(f *frame) {
			f.WindowsServiceStartup.CollectedAt = f.WindowsInventory.CollectedAt.Add(-time.Nanosecond)
		},
		"future":        func(f *frame) { f.WindowsServiceStartup.CollectedAt = f.Observation.GeneratedAt.Add(time.Second) },
		"missing":       func(f *frame) { f.WindowsServiceStartup = nil },
		"contradiction": func(f *frame) { f.WindowsServiceStartup.Rows[0].DelayedAutoStart = new(bool) },
	}
	for _, version := range []string{FrameWindowsInventoryVersion, FrameWindowsEventsVersion, FrameWindowsCapabilitiesVersion, FrameWindowsProcessMetricsVersion, FrameWindowsNetworkVersion} {
		v := version
		changes[v] = func(f *frame) { f.SchemaVersion = v }
	}
	check := func(t *testing.T, b []byte) {
		t.Helper()
		if _, e := lanstore.ValidateFrame(b, time.Now().UTC()); e == nil {
			t.Fatal("invalid ingress accepted")
		}
		if _, e := decodeFrameForConfig(b, 1, m.config); e == nil {
			t.Fatal("invalid pending accepted")
		}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var copy frame
			json.Unmarshal(raw, &copy)
			change(&copy)
			b, _ := json.Marshal(copy)
			check(t, b)
		})
	}
	for name, extra := range map[string]string{"null": "\"windowsNetwork\":null,", "unknown": "\"extra\":false,", "duplicate": "\"sequence\":1,"} {
		t.Run(name, func(t *testing.T) { check(t, append([]byte("{"+extra), raw[1:]...)) })
	}
	var missing frame
	json.Unmarshal(raw, &missing)
	missing.WindowsServiceStartup = nil
	bad, _ := json.Marshal(missing)
	check(t, bad)
}

func TestWindowsServiceStartupCaptureFloorAndPreSendRevocation(t *testing.T) {
	t.Run("capture-floor", func(t *testing.T) {
		f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
		baseAt := time.Now().UTC().Add(-time.Second)
		first, _, e := collectWindowsFrame(context.Background(), f.material.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
			return windowsmanaged.FromReport(syntheticWindowsReport(baseAt), g)
		})
		if e != nil {
			t.Fatal(e)
		}
		first, raw, e := appendWindowsServiceStartup(context.Background(), f.material, first, serviceStartupConsentFixture(f.material), serviceStartupSourceFixture)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
			t.Fatal(e)
		}
		first.Sequence = 2
		first.WindowsInventory.GenerationID = "sample_" + strings.Repeat("b", 32)
		first.WindowsServiceStartup.GenerationID = first.WindowsInventory.GenerationID
		first.WindowsInventory.CollectedAt = first.WindowsInventory.CollectedAt.Add(time.Nanosecond)
		first.Observation.Observation.LastSeen = first.Observation.Observation.LastSeen.Add(time.Nanosecond)
		first.Observation.GeneratedAt = first.Observation.GeneratedAt.Add(time.Nanosecond)
		raw, _ = json.Marshal(first)
		if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
			t.Fatal("invalid replay fixture", e)
		}
		if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); !errors.Is(e, lanstore.ErrReplay) {
			t.Fatal("startup capture floor bypass", e)
		}
		if got := f.view(t, time.Now().UTC()); got.Sequence == nil || *got.Sequence != 1 {
			t.Fatal("rejected startup capture modified durable view")
		}
	})
	t.Run("before-send", func(t *testing.T) {
		m := windowsMaterialFixture(t, "http-test")
		state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
		if e != nil {
			t.Fatal(e)
		}
		defer state.Close()
		c := serviceStartupConsentFixture(m)
		reads, sends := 0, 0
		_, e = runUsingStateWithServiceStartupDependencies(context.Background(), m, state, nil, nil, nil, windowsSource, func(*http.Request) (*http.Response, error) { sends++; return nil, errors.New("must never send") }, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsmanaged.ServiceStartupConsent, bool) { reads++; return c, reads < 4 }, serviceStartupSourceFixture)
		if !errors.Is(e, ErrState) || sends != 0 || reads != 4 {
			t.Fatal("revocation immediately before send was ignored", e, reads, sends)
		}
		pending, e := state.Pending()
		if e != nil || pending == nil {
			t.Fatal("unsent staged bytes were erased/reset", e)
		}
	})
}

func TestWindowsServiceStartupCaptureFloorSurvivesAbsentScope(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	baseAt := time.Now().UTC().Add(-time.Second)
	first, _, e := collectWindowsFrame(context.Background(), f.material.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		return windowsmanaged.FromReport(syntheticWindowsReport(baseAt), g)
	})
	if e != nil {
		t.Fatal(e)
	}
	first, raw, e := appendWindowsServiceStartup(context.Background(), f.material, first, serviceStartupConsentFixture(f.material), serviceStartupSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	startupAt := first.WindowsServiceStartup.CollectedAt
	first.SchemaVersion = FrameWindowsInventoryVersion
	first.WindowsServiceStartup = nil
	first.Sequence = 2
	first.WindowsInventory.GenerationID = "sample_" + strings.Repeat("b", 32)
	first.WindowsInventory.CollectedAt = startupAt.Add(-time.Nanosecond)
	first.Observation.Observation.LastSeen = first.WindowsInventory.CollectedAt
	first.Observation.GeneratedAt = time.Now().UTC()
	raw, _ = json.Marshal(first)
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal("invalid absent-scope fixture", e)
	}
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); !errors.Is(e, lanstore.ErrReplay) {
		t.Fatal("scope omission erased startup capture floor", e)
	}
	first.WindowsInventory.CollectedAt = startupAt.Add(time.Nanosecond)
	first.Observation.Observation.LastSeen = first.WindowsInventory.CollectedAt
	first.Observation.GeneratedAt = time.Now().UTC()
	raw, _ = json.Marshal(first)
	if _, e = f.store.SaveObservation(context.Background(), f.identity.InvitationID, f.identity.Issuance.CertificateHash, raw, time.Now().UTC()); e != nil {
		t.Fatal("legitimate scope disable blocked", e)
	}
	if got := f.view(t, time.Now().UTC()); got.Network != nil || got.Sequence == nil || *got.Sequence != 2 {
		t.Fatal("scope disable failed")
	}
}

func TestWindowsServiceStartupMaximalCombinedEnvelopePreservesBaseAndCapture(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	collect := func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		for i := 1; i <= 128; i++ {
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: uint32(i), Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Services.Quality, r.Services.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("x", 60), DisplayName: "Fixture", State: "running", PID: 7})
		}
		r.Software.Quality = "healthy"
		r.Software.Complete = true
		for i := 1; i <= 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		return windowsmanaged.FromReport(r, g)
	}
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, collect)
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 3700), strings.Repeat("b", 3700), strings.Repeat("c", 3700)}
	f, _, err = appendWindowsEvents(context.Background(), m, f, eventConsentFixture(m), eventSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	original, err := volumeSourceFixture(context.Background(), f.WindowsInventory.GenerationID, volumeConsentFixture(m), m.binding)
	if err != nil {
		t.Fatal(err)
	}
	original.Rows = nil
	original.ObservedCount = 64
	original.Complete = false
	original.Truncated = true
	original.Quality = "bounded"
	for i := 0; i < 40; i++ {
		original.Rows = append(original.Rows, windowsvolumes.Volume{VolumeID: fmt.Sprintf(`\\?\Volume{11111111-2222-3333-4444-%012x}\`, i), DriveType: "fixed", Quality: "observed", Capacity: &windowsvolumes.Capacity{TotalBytes: "18446744073709551615", FreeBytes: "18446744073709551615", AvailableBytes: "18446744073709551615"}})
	}
	original, err = windowsvolumes.FitBudget(original, windowsvolumes.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsVolumes(context.Background(), m, f, volumeConsentFixture(m), func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error) {
		return original, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsVolumes.CollectedAt.Equal(original.CollectedAt) || f.WindowsVolumes.ObservedCount != 64 || !f.WindowsVolumes.CountExact || !f.WindowsVolumes.Truncated || len(f.WindowsVolumes.Rows) >= len(original.Rows) {
		t.Fatal("envelope trim lost truth or failed to exercise remaining budget", len(raw), len(f.WindowsVolumes.Rows), len(original.Rows))
	}
	volumeCapture := f.WindowsVolumes.CollectedAt
	volumeCount := f.WindowsVolumes.ObservedCount
	metrics, err := processSourceFixture(context.Background(), func() []uint32 {
		ids := []uint32{}
		for _, p := range f.WindowsInventory.Processes.Rows {
			ids = append(ids, p.PID)
		}
		return ids
	}(), f.WindowsInventory.GenerationID, processConsentFixture(m).GrantID, f.WindowsInventory.CollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	metricCapture := metrics.CollectedAt
	f, raw, err = appendWindowsProcessMetrics(context.Background(), m, f, processConsentFixture(m), func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
		return metrics, nil
	})
	if err != nil {
		t.Fatal("full v3 frame blocked v4", err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsVolumes.CollectedAt.Equal(volumeCapture) || f.WindowsVolumes.ObservedCount != volumeCount || !f.WindowsProcessMetrics.CollectedAt.Equal(metricCapture) || int(f.WindowsProcessMetrics.ObservedCount) != len(f.WindowsInventory.Processes.Rows) {
		t.Fatal("combined trim lost capture/count")
	}
	network, err := networkSourceFixture(context.Background(), f.WindowsInventory.GenerationID, networkConsentFixture(m).GrantID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	capture := network.CollectedAt
	f, raw, err = appendWindowsNetwork(context.Background(), m, f, networkConsentFixture(m), func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error) { return network, nil })
	if err != nil {
		t.Fatal("full v4 blocked v5", err)
	}
	if len(raw) > MaxFrameBytes || !f.WindowsNetwork.CollectedAt.Equal(capture) || f.WindowsNetwork.ObservedCount != 1 || !f.WindowsVolumes.CollectedAt.Equal(volumeCapture) || f.WindowsVolumes.ObservedCount != volumeCount || !f.WindowsProcessMetrics.CollectedAt.Equal(metricCapture) {
		t.Fatal("network trim lost captures/count")
	}

	baseBefore, _ := json.Marshal(f.WindowsInventory)
	digest, err := windowsmanaged.ServiceStartupRowsSHA256(f.WindowsInventory.Services.Rows)
	if err != nil || len(f.WindowsInventory.Services.Rows) == 0 {
		t.Fatal("maximal service fixture lost all rows", err)
	}
	startup, err := serviceStartupSourceFixture(context.Background(), f.WindowsInventory.Services.Rows, f.WindowsInventory.GenerationID, serviceStartupConsentFixture(m).GrantID, f.WindowsInventory.CollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	startupAt, startupCount := startup.CollectedAt, startup.RequestedCount
	f, raw, err = appendWindowsServiceStartup(context.Background(), m, f, serviceStartupConsentFixture(m), func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		return startup, nil
	})
	if err != nil {
		t.Fatal("full v5 blocked v6", err)
	}
	baseAfter, _ := json.Marshal(f.WindowsInventory)
	if !bytes.Equal(baseBefore, baseAfter) || len(raw) > MaxFrameBytes || f.WindowsServiceStartup.ServicesSHA256 != digest || f.WindowsServiceStartup.RequestedCount != startupCount || !f.WindowsServiceStartup.CollectedAt.Equal(startupAt) || !f.WindowsNetwork.CollectedAt.Equal(capture) || !f.WindowsVolumes.CollectedAt.Equal(volumeCapture) || !f.WindowsProcessMetrics.CollectedAt.Equal(metricCapture) {
		t.Fatal("v6 trim changed base/digest/capture/count")
	}

	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsServiceStartupRechecksGrantImmediatelyBeforeNativeSeam(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := serviceStartupConsentFixture(m)
	calls := 0
	_, e = runUsingStateWithServiceStartupDependencies(context.Background(), m, state, nil, nil, nil, func(ctx context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		s, d, e := startupWindowsSource(ctx, g)
		c.Enabled = false
		return s, d, e
	}, func(*http.Request) (*http.Response, error) { t.Fatal("revoked grant transmitted"); return nil, nil }, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsmanaged.ServiceStartupConsent, bool) { return c, c.Enabled }, func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
		calls++
		return windowsmanaged.ServiceStartupSnapshot{}, nil
	})
	if !errors.Is(e, ErrState) || calls != 0 {
		t.Fatal("revoked grant reached startup read", e, calls)
	}
}
