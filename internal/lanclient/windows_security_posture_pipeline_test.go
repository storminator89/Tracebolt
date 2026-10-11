//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func securityConsentFixture(m Material) windowssecurity.Consent {
	return windowssecurity.Consent{SchemaVersion: windowssecurity.ConsentVersion, Scope: windowssecurity.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("6", 32), Enabled: true}
}
func securitySourceFixture(_ context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
	s := windowssecurity.Empty(r, windowssecurity.ErrUnavailable.Error())
	version := "1.451.12.0"
	age := uint32(1)
	s.Defender = windowssecurity.Defender{Quality: "observed", Mode: "passive", ServiceEnabled: "on", AntivirusEnabled: "off", RealTimeProtectionEnabled: "off", SignatureVersion: &version, SignatureAgeDays: &age}
	s.Firewall = windowssecurity.Firewall{Quality: "observed", Profiles: []windowssecurity.Profile{{Profile: "domain", Active: "off", Enabled: "on"}, {Profile: "private", Active: "on", Enabled: "on"}, {Profile: "public", Active: "off", Enabled: "off"}}}
	return s, nil
}

func runSecurityOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowssecurity.Consent, bool), collect securityPostureCollector) (Report, error) {
	return runUsingStateWithSecurityPostureDependencies(ctx, m, s, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect)
}
func TestWindowsSecurityPostureEndToEndSelectionsAndAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, selection := range []string{"off", "patch-only", "all"} {
			t.Run(transport+"/"+selection, func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				ec, vc, pc, nc, sc, uc, ac, patch := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material), updatesConsentFixture(f.material), adapterConsentFixture(f.material), securityConsentFixture(f.material)
				all := selection == "all"
				patch.Enabled = selection != "off"
				calls := 0
				var sent frame
				_, e = runUsingStateWithSecurityPostureDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, all }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, all }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, all }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, all }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, all }, serviceStartupSourceFixture, func() (windowsupdates.Consent, bool) { return uc, all }, updatesSourceFixture, func() (windowsadapters.Consent, bool) { return ac, all }, adapterSourceFixture, func() (windowspatchcontext.Consent, bool) { return patchConsentFixture(f.material), all }, patchSourceFixture, func() (windowssecurity.Consent, bool) { return patch, patch.Enabled }, func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
					calls++
					return securitySourceFixture(ctx, r)
				})
				if e != nil {
					t.Fatal(e)
				}
				v := f.view(t, time.Now().UTC())
				if (v.SecurityPosture != nil) != patch.Enabled || calls != map[bool]int{true: 1, false: 0}[patch.Enabled] {
					t.Fatal("scope")
				}
				if !patch.Enabled {
					if sent.SchemaVersion != FrameWindowsInventoryVersion {
						t.Fatal("old frame promoted")
					}
					return
				}
				if sent.SchemaVersion != FrameWindowsSecurityPostureVersion || v.SecurityPosture.Defender.Mode != "passive" || v.SecurityPosture.Firewall.Profiles[2].Enabled != "off" || !v.SecurityPosture.CollectedAt.Equal(v.Snapshot.CollectedAt) {
					t.Fatal("lost source")
				}
				if (v.AdapterContext != nil) != all || (v.Updates != nil) != all {
					t.Fatal("sibling promotion")
				}
				basic, e := f.store.LatestObservations(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(basic)
				if bytes.Contains(raw, []byte("1.451.12.0")) || bytes.Contains(raw, []byte("securityPosture")) {
					t.Fatal("private export")
				}
				stale, e := v.RecheckAt(v.ServerNow.Add(3 * time.Minute))
				if e != nil || stale.Status != "stale" || stale.SecurityPosture == nil {
					t.Fatal("stale", e)
				}
				expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
				if e != nil || expired.SecurityPosture != nil {
					t.Fatal("expiry", e)
				}
				v.Status = "revoked"
				revoked, e := v.RecheckAt(v.ServerNow)
				if e != nil || revoked.SecurityPosture != nil {
					t.Fatal("authority", e)
				}
			})
		}
	}
}
func TestWindowsSecurityPostureRetryRestartAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := securityConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runSecurityOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(raw))
			req.Body = io.NopCloser(bytes.NewReader(raw))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("fixture lost response")
			}
			return response, nil
		}, func() (windowssecurity.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
			calls++
			return securitySourceFixture(ctx, r)
		})
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	before := f.view(t, time.Now().UTC())
	state.Close()
	f.store.Close()
	f.open(t)
	state, e = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	report, e := run()
	if e != nil || !report.RetriedPending || calls != 1 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry", e)
	}
	after := f.view(t, time.Now().UTC())
	if !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.SecurityPosture.CollectedAt.Equal(before.SecurityPosture.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runSecurityOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowssecurity.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowssecurity.Request) (windowssecurity.Snapshot, error) {
		s, e := securitySourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked captured source sent")
	}
}

func TestWindowsSecurityPostureFrameRejectsCrossScopeAndUnknownData(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := context.Background()
	base, _, e := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	good, raw, e := appendWindowsSecurityPosture(ctx, m, base, securityConsentFixture(m), securitySourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "generation", "capture", "duplicate-grant", "extra", "false-observed", "unknown-mode"} {
		copy := good
		s := *good.WindowsSecurityPosture
		copy.WindowsSecurityPosture = &s
		switch kind {
		case "old-wire":
			copy.SchemaVersion = FrameWindowsPatchContextVersion
		case "missing":
			copy.WindowsSecurityPosture = nil
		case "generation":
			s.GenerationID = "sample_" + strings.Repeat("1", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			patch, _ := patchSourceFixture(ctx, windowspatchcontext.Request{Consent: patchConsentFixture(m), SenderBinding: m.binding, GenerationID: base.WindowsInventory.GenerationID, CollectedAt: base.WindowsInventory.CollectedAt})
			copy.WindowsPatchContext = &patch
			s.GrantID = patch.GrantID
		case "false-observed":
			s.Defender.Mode = "unknown"
		case "unknown-mode":
			s.Defender.Mode = "unprotected"
		}
		bad, _ := json.Marshal(copy)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"defender":`), []byte(`"rules":["private"],"defender":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
	if lanstore.FrameMatchesCollectionProfile(lanstore.Frame{SchemaVersion: FrameWindowsSecurityPostureVersion, WindowsSecurityPosture: good.WindowsSecurityPosture}, "basic-readonly-v1") {
		t.Fatal("basic profile expanded")
	}
}

func TestWindowsSecurityPostureAllBlockedOptionalSourcesStillSendBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	u, p, c := updatesConsentFixture(m), patchConsentFixture(m), securityConsentFixture(m)
	parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	calls := 0
	var sent frame
	_, e = runUsingStateWithSecurityPostureDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
		if parent.Err() != nil {
			t.Fatal("outer deadline consumed")
		}
		if json.NewDecoder(req.Body).Decode(&sent) != nil {
			t.Fatal("frame")
		}
		return nil, errors.New("fixture offline")
	}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowsupdates.Consent, bool) { return u, true }, func(ctx context.Context, _ windowsupdates.Request) (windowsupdates.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowsupdates.Snapshot{}, ctx.Err()
	}, nil, nil, func() (windowspatchcontext.Consent, bool) { return p, true }, func(ctx context.Context, _ windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowspatchcontext.Snapshot{}, ctx.Err()
	}, func() (windowssecurity.Consent, bool) { return c, true }, func(ctx context.Context, _ windowssecurity.Request) (windowssecurity.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowssecurity.Snapshot{}, ctx.Err()
	})
	if !errors.Is(e, ErrTransport) || calls != 3 || sent.WindowsInventory == nil || sent.WindowsSecurityPosture == nil || sent.WindowsUpdates == nil || sent.WindowsPatchContext == nil || sent.WindowsSecurityPosture.Defender.Reason != windowssecurity.ErrBudget.Error() || sent.WindowsSecurityPosture.Firewall.Reason != windowssecurity.ErrBudget.Error() {
		t.Fatal("optional sources suppressed base", calls, e)
	}
	if !sent.WindowsSecurityPosture.CollectedAt.Equal(sent.WindowsInventory.CollectedAt) {
		t.Fatal("capture refreshed")
	}
}
