//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func sessionConsentFixture(m Material) windowssessions.Consent {
	return windowssessions.Consent{SchemaVersion: windowssessions.ConsentVersion, Scope: windowssessions.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("5", 32), Enabled: true}
}
func sessionSourceFixture(_ context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
	s := windowssessions.Empty(r, windowssessions.ErrUnavailable.Error())
	name := "DEMO-WORKGROUP"
	user := "demo-private-user"
	n := uint32(1)
	zero := uint32(0)
	s.Sessions = windowssessions.Sessions{Quality: "observed", ObservedCount: &n, RetainedCount: 1, TruncatedCount: &zero, Rows: []windowssessions.Session{{SessionID: 1, UserName: &user, UserQuality: "observed", DomainQuality: "empty", State: "active", Protocol: "console"}}}
	s.Join = windowssessions.Join{Quality: "observed", Status: "workgroup", Name: &name}

	return s, nil
}

func runSessionOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowssessions.Consent, bool), collect sessionContextCollector) (Report, error) {
	return runUsingStateWithSessionContextDependencies(ctx, m, s, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect)
}
func TestWindowsSessionContextEndToEndSelectionsAndAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, selection := range []string{"off", "session-only", "all"} {
			t.Run(transport+"/"+selection, func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				ec, vc, pc, nc, sc, uc, ac, patch := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material), updatesConsentFixture(f.material), adapterConsentFixture(f.material), sessionConsentFixture(f.material)
				all := selection == "all"
				patch.Enabled = selection != "off"
				calls := 0
				var sent frame
				_, e = runUsingStateWithSessionContextAuthorityDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, all }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, all }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, all }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, all }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, all }, serviceStartupSourceFixture, func() (windowsupdates.Consent, bool) { return uc, all }, updatesSourceFixture, func() (windowsadapters.Consent, bool) { return ac, all }, adapterSourceFixture, func() (windowspatchcontext.Consent, bool) { return patchConsentFixture(f.material), all }, patchSourceFixture, func() (windowssecurity.Consent, bool) { return securityConsentFixture(f.material), all }, securitySourceFixture, func() (windowssessions.Consent, bool) { return patch, patch.Enabled }, func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
					calls++
					return sessionSourceFixture(ctx, r)
				}, func() bool { return true })
				if e != nil {
					t.Fatal(e)
				}
				v := f.view(t, time.Now().UTC())
				if (v.SessionContext != nil) != patch.Enabled || calls != map[bool]int{true: 1, false: 0}[patch.Enabled] {
					t.Fatal("scope")
				}
				if !patch.Enabled {
					if sent.SchemaVersion != FrameWindowsInventoryVersion {
						t.Fatal("old frame promoted")
					}
					return
				}
				if sent.SchemaVersion != FrameWindowsSessionContextVersion || v.SessionContext.Sessions.Rows[0].Protocol != "console" || v.SessionContext.Join.Status != "workgroup" || !v.SessionContext.CollectedAt.Equal(v.Snapshot.CollectedAt) {
					t.Fatal("lost source")
				}
				if (v.AdapterContext != nil) != all || (v.Updates != nil) != all || (v.SecurityPosture != nil) != all {
					t.Fatal("sibling promotion")
				}
				basic, e := f.store.LatestObservations(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(basic)
				if bytes.Contains(raw, []byte("demo-private-user")) || bytes.Contains(raw, []byte("sessionContext")) {
					t.Fatal("private export")
				}
				stale, e := v.RecheckAt(v.ServerNow.Add(3 * time.Minute))
				if e != nil || stale.Status != "stale" || stale.SessionContext == nil {
					t.Fatal("stale", e)
				}
				expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
				if e != nil || expired.SessionContext != nil {
					t.Fatal("expiry", e)
				}
				v.Status = "revoked"
				revoked, e := v.RecheckAt(v.ServerNow)
				if e != nil || revoked.SessionContext != nil {
					t.Fatal("authority", e)
				}
			})
		}
	}
}
func TestWindowsSessionContextRetryRestartAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := sessionConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runSessionOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(raw))
			req.Body = io.NopCloser(bytes.NewReader(raw))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("fixture lost response")
			}
			return response, nil
		}, func() (windowssessions.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
			calls++
			return sessionSourceFixture(ctx, r)
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
	if !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.SessionContext.CollectedAt.Equal(before.SessionContext.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runSessionOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowssessions.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
		s, e := sessionSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked captured source sent")
	}
}

func TestWindowsSessionContextFrameRejectsCrossScopeAndUnknownData(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := context.Background()
	base, _, e := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	good, raw, e := appendWindowsSessionContext(ctx, m, base, sessionConsentFixture(m), sessionSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "generation", "capture", "duplicate-grant", "extra", "false-observed", "unknown-mode"} {
		copy := good
		s := *good.WindowsSessionContext
		copy.WindowsSessionContext = &s
		switch kind {
		case "old-wire":
			copy.SchemaVersion = FrameWindowsPatchContextVersion
		case "missing":
			copy.WindowsSessionContext = nil
		case "generation":
			s.GenerationID = "sample_" + strings.Repeat("1", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			patch, _ := patchSourceFixture(ctx, windowspatchcontext.Request{Consent: patchConsentFixture(m), SenderBinding: m.binding, GenerationID: base.WindowsInventory.GenerationID, CollectedAt: base.WindowsInventory.CollectedAt})
			copy.WindowsPatchContext = &patch
			s.GrantID = patch.GrantID
		case "false-observed":
			s.Sessions.Rows = append([]windowssessions.Session{}, s.Sessions.Rows...)
			s.Sessions.Rows[0].Protocol = "unknown"
		case "unknown-mode":
			s.Join.Status = "protected"
		}
		bad, _ := json.Marshal(copy)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"sessions":`), []byte(`"rules":["private"],"sessions":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
	if lanstore.FrameMatchesCollectionProfile(lanstore.Frame{SchemaVersion: FrameWindowsSessionContextVersion, WindowsSessionContext: good.WindowsSessionContext}, "basic-readonly-v1") {
		t.Fatal("basic profile expanded")
	}
}

func TestWindowsSessionContextAllBlockedOptionalSourcesStillSendBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	u, p, c := updatesConsentFixture(m), patchConsentFixture(m), sessionConsentFixture(m)
	parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	calls := 0
	var sent frame
	_, e = runUsingStateWithSessionContextAuthorityDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
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
	}, func() (windowssecurity.Consent, bool) { return securityConsentFixture(m), true }, func(ctx context.Context, _ windowssecurity.Request) (windowssecurity.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowssecurity.Snapshot{}, ctx.Err()
	}, func() (windowssessions.Consent, bool) { return c, true }, func(ctx context.Context, _ windowssessions.Request) (windowssessions.Snapshot, error) {
		calls++
		<-ctx.Done()
		return windowssessions.Snapshot{}, ctx.Err()
	}, func() bool { return true })
	if !errors.Is(e, ErrTransport) || calls != 4 || sent.WindowsSecurityPosture == nil || sent.WindowsInventory == nil || sent.WindowsSessionContext == nil || sent.WindowsUpdates == nil || sent.WindowsPatchContext == nil || sent.WindowsSessionContext.Sessions.Reason != windowssessions.ErrBudget.Error() || sent.WindowsSessionContext.Join.Reason != windowssessions.ErrBudget.Error() {
		t.Fatal("optional sources suppressed base", calls, e)
	}
	if !sent.WindowsSessionContext.CollectedAt.Equal(sent.WindowsInventory.CollectedAt) {
		t.Fatal("capture refreshed")
	}
}

func TestWindowsSessionContextFrameBudgetPreservesBaseAndSelf(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := withProcessMetricSelfPID(context.Background(), 7)
	f, _, err := collectWindowsFrame(context.Background(), m.config, 1, func(_ context.Context, g string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		r.Processes.Rows = []windowsinventory.Process{}
		for i := 1; i <= 128; i++ {
			r.Processes.Rows = append(r.Processes.Rows, windowsinventory.Process{PID: uint32(i), Name: strings.Repeat("p", 250), Threads: 1})
		}
		r.Services.Quality, r.Services.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Services.Rows = append(r.Services.Rows, windowsinventory.Service{Name: fmt.Sprintf("Service%03d", i) + strings.Repeat("x", 60), DisplayName: "Fixture", State: "running", PID: 7})
		}
		r.Software.Quality, r.Software.Complete = "healthy", true
		for i := 1; i <= 128; i++ {
			r.Software.Rows = append(r.Software.Rows, windowsinventory.Software{Name: fmt.Sprintf("%03d", i) + strings.Repeat("s", 240), Version: "1", Publisher: "Fixture", RegistryView: "64"})
		}
		return windowsmanaged.FromReport(r, g)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Observation.Privacy = []string{strings.Repeat("a", 2500), strings.Repeat("b", 2500), strings.Repeat("c", 2500)}
	f, _, err = appendWindowsEvents(ctx, m, f, eventConsentFixture(m), eventSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), volumeSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), processSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(f.WindowsInventory)
	digest := f.WindowsServiceStartup.ServicesSHA256
	capture := f.WindowsInventory.CollectedAt
	f, _, err = appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), updatesSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsAdapterContext(ctx, m, f, adapterConsentFixture(m), adapterSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = appendWindowsSecurityPosture(ctx, m, f, securityConsentFixture(m), securitySourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := appendWindowsSessionContext(ctx, m, f, sessionConsentFixture(m), func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
		s, e := sessionSourceFixture(ctx, r)
		n := uint32(32)
		zero := uint32(0)
		s.Sessions.ObservedCount = &n
		s.Sessions.RetainedCount = n
		s.Sessions.TruncatedCount = &zero
		s.Sessions.Rows = []windowssessions.Session{}
		for i := uint32(1); i <= 32; i++ {
			name := strings.Repeat("界", 64)
			s.Sessions.Rows = append(s.Sessions.Rows, windowssessions.Session{SessionID: i, UserName: &name, UserQuality: "observed", DomainName: &name, DomainQuality: "observed", State: "active", Protocol: "rdp"})
		}
		return s, e
	})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.WindowsInventory)
	if len(raw) > MaxFrameBytes || !bytes.Equal(base, after) || f.WindowsServiceStartup.ServicesSHA256 != digest || !f.WindowsSessionContext.CollectedAt.Equal(capture) || *f.WindowsSessionContext.Sessions.ObservedCount != 32 || *f.WindowsSessionContext.Sessions.TruncatedCount == 0 || f.WindowsSessionContext.Sessions.RetainedCount+*f.WindowsSessionContext.Sessions.TruncatedCount != 32 {
		t.Fatal("budget lost original capture/binding")
	}
	if _, err = lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	self := false
	for _, v := range f.WindowsProcessMetrics.Rows {
		if v.PID == 7 {
			self = true
		}
	}
	if !self {
		t.Fatal("protected self metric trimmed")
	}
}

func TestWindowsSessionContextOldV10RetryBytesAndReplacement(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	security := securityConsentFixture(m)
	session := sessionConsentFixture(m)
	enabled := false
	calls := 0
	var sent [][]byte
	run := func() (Report, error) {
		return runUsingStateWithSessionContextAuthorityDependencies(context.Background(), m, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			sent = append(sent, b)
			return nil, errors.New("fixture offline")
		}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, func() (windowssecurity.Consent, bool) { return security, true }, securitySourceFixture, func() (windowssessions.Consent, bool) { return session, enabled }, func(ctx context.Context, r windowssessions.Request) (windowssessions.Snapshot, error) {
			calls++
			return sessionSourceFixture(ctx, r)
		}, func() bool { return true })
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	first, e := state.Pending()
	if e != nil || first == nil {
		t.Fatal(e)
	}
	var old frame
	json.Unmarshal(first.Body(), &old)
	if old.SchemaVersion != FrameWindowsSecurityPostureVersion || old.WindowsSessionContext != nil {
		t.Fatal("old wire promoted")
	}
	if r, e := run(); !errors.Is(e, ErrTransport) || !r.RetriedPending || calls != 0 || len(sent) != 2 || !bytes.Equal(sent[0], sent[1]) {
		t.Fatal("old retry bytes changed", e)
	}
	// A newly enabled scope cannot rewrite an existing old pending frame.
	enabled = true
	if r, e := run(); !errors.Is(e, ErrTransport) || !r.RetriedPending || calls != 0 || !bytes.Equal(sent[0], sent[2]) {
		t.Fatal("new grant rewrote old pending", e)
	}
	if e = state.Acknowledge(first.Digest); e != nil {
		t.Fatal(e)
	}
	if _, e = run(); !errors.Is(e, ErrTransport) || calls != 1 {
		t.Fatal("new source missing", e)
	}
	before := len(sent)
	session.GrantID = strings.Repeat("4", 32)
	r, e := run()
	if !errors.Is(e, ErrTransport) || !r.DiscardedUnconsented || r.RetriedPending || len(sent) != before+1 || calls != 2 {
		t.Fatal("replaced personal metadata retried", e, r)
	}
	var replacement frame
	json.Unmarshal(sent[len(sent)-1], &replacement)
	if replacement.WindowsSessionContext == nil || replacement.WindowsSessionContext.GrantID != session.GrantID || bytes.Equal(sent[len(sent)-1], sent[len(sent)-2]) {
		t.Fatal("replacement did not capture under fresh grant")
	}
}
