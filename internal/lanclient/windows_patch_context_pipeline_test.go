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
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func patchConsentFixture(m Material) windowspatchcontext.Consent {
	return windowspatchcontext.Consent{SchemaVersion: windowspatchcontext.ConsentVersion, Scope: windowspatchcontext.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("7", 32), Enabled: true}
}
func patchSourceFixture(_ context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
	s := windowspatchcontext.Empty(r, "")
	s.Reboot = windowspatchcontext.Reboot{WindowsUpdate: "pending", Servicing: "clear", FileOperations: "unavailable"}
	s.History = windowspatchcontext.History{Quality: "observed", CountExact: true, TotalCount: 1, Rows: []windowspatchcontext.Entry{{UpdateID: "12345678-1234-1234-1234-123456789abc", Revision: 1, Title: "Synthetic private retained patch", OccurredAt: r.CollectedAt.Add(-time.Hour), Operation: "installation", Result: "succeeded", HResult: "00000000"}}}
	return s, nil
}
func runPatchOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowspatchcontext.Consent, bool), collect patchContextCollector) (Report, error) {
	return runUsingStateWithPatchContextDependencies(ctx, m, s, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect)
}
func TestWindowsPatchContextEndToEndSelectionsAndAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, selection := range []string{"off", "patch-only", "all"} {
			t.Run(transport+"/"+selection, func(t *testing.T) {
				f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
				state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				ec, vc, pc, nc, sc, uc, ac, patch := eventConsentFixture(f.material), volumeConsentFixture(f.material), processConsentFixture(f.material), networkConsentFixture(f.material), serviceStartupConsentFixture(f.material), updatesConsentFixture(f.material), adapterConsentFixture(f.material), patchConsentFixture(f.material)
				all := selection == "all"
				patch.Enabled = selection != "off"
				calls := 0
				var sent frame
				_, e = runUsingStateWithPatchContextDependencies(context.Background(), f.material, state, nil, nil, nil, startupWindowsSource, func(req *http.Request) (*http.Response, error) {
					raw, _ := io.ReadAll(req.Body)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return startupServe(t, f, req), nil
				}, func() (windowseventhealth.Consent, bool) { return ec, all }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return vc, all }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return pc, all }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return nc, all }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) { return sc, all }, serviceStartupSourceFixture, func() (windowsupdates.Consent, bool) { return uc, all }, updatesSourceFixture, func() (windowsadapters.Consent, bool) { return ac, all }, adapterSourceFixture, func() (windowspatchcontext.Consent, bool) { return patch, patch.Enabled }, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
					calls++
					return patchSourceFixture(ctx, r)
				})
				if e != nil {
					t.Fatal(e)
				}
				v := f.view(t, time.Now().UTC())
				if (v.PatchContext != nil) != patch.Enabled || calls != map[bool]int{true: 1, false: 0}[patch.Enabled] {
					t.Fatal("scope")
				}
				if !patch.Enabled {
					if sent.SchemaVersion != FrameWindowsInventoryVersion {
						t.Fatal("old frame promoted")
					}
					return
				}
				if sent.SchemaVersion != FrameWindowsPatchContextVersion || v.PatchContext.Reboot.WindowsUpdate != "pending" || !v.PatchContext.CollectedAt.Equal(v.Snapshot.CollectedAt) {
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
				if bytes.Contains(raw, []byte("Synthetic private retained patch")) || bytes.Contains(raw, []byte("patchContext")) {
					t.Fatal("private export")
				}
				stale, e := v.RecheckAt(v.ServerNow.Add(3 * time.Minute))
				if e != nil || stale.Status != "stale" || stale.PatchContext == nil {
					t.Fatal("stale", e)
				}
				expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
				if e != nil || expired.PatchContext != nil {
					t.Fatal("expiry", e)
				}
				v.Status = "revoked"
				revoked, e := v.RecheckAt(v.ServerNow)
				if e != nil || revoked.PatchContext != nil {
					t.Fatal("authority", e)
				}
			})
		}
	}
}
func TestWindowsPatchContextRetryRestartAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := patchConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runPatchOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(raw))
			req.Body = io.NopCloser(bytes.NewReader(raw))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("fixture lost response")
			}
			return response, nil
		}, func() (windowspatchcontext.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
			calls++
			return patchSourceFixture(ctx, r)
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
	if !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.PatchContext.CollectedAt.Equal(before.PatchContext.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runPatchOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowspatchcontext.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		s, e := patchSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked captured source sent")
	}
}
func TestWindowsPatchContextFrameAdmissionAndBudget(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := context.Background()
	base, _, e := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	c := patchConsentFixture(m)
	good, raw, e := appendWindowsPatchContext(ctx, m, base, c, patchSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "rebound", "capture", "duplicate-grant", "extra"} {
		f := good
		s := *good.WindowsPatchContext
		f.WindowsPatchContext = &s
		switch kind {
		case "old-wire":
			f.SchemaVersion = FrameWindowsInventoryVersion
		case "missing":
			f.WindowsPatchContext = nil
		case "rebound":
			s.GenerationID = "sample_" + strings.Repeat("b", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			u, _ := updatesSourceFixture(ctx, windowsupdates.Request{Consent: updatesConsentFixture(m), SenderBinding: m.binding, GenerationID: base.WindowsInventory.GenerationID, CollectedAt: base.WindowsInventory.CollectedAt})
			s.GrantID = u.GrantID
			f.WindowsUpdates = &u
		}
		bad, _ := json.Marshal(f)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"os":`), []byte(`"owner":"private","os":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
	before, _ := json.Marshal(base.WindowsInventory)
	for i := 0; i < 14; i++ {
		base.Observation.Privacy = append(base.Observation.Privacy, strings.Repeat("x", 600))
	}
	base.Observation.Privacy = base.Observation.Privacy[:14]
	_, _, e = appendWindowsPatchContext(ctx, m, base, c, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
		s, _ := patchSourceFixture(ctx, r)
		s.History.Rows = []windowspatchcontext.Entry{}
		s.History.TotalCount = 64
		for i := 0; i < 64; i++ {
			row := windowspatchcontext.Entry{Index: uint32(i), UpdateID: "12345678-1234-1234-1234-123456789abc", Revision: 1, Title: strings.Repeat("x", 256), OccurredAt: r.CollectedAt.Add(-time.Duration(i+1) * time.Hour), Operation: "installation", Result: "succeeded", HResult: "00000000"}
			s.History.Rows = append(s.History.Rows, row)
		}
		encoded, _ := json.Marshal(s)
		if len(encoded) > windowspatchcontext.MaxBytes { // Native contract fits before sender entry.
			for len(encoded) > windowspatchcontext.MaxBytes {
				s.History.Rows = s.History.Rows[:len(s.History.Rows)-1]
				s.History.Truncated = true
				encoded, _ = json.Marshal(s)
			}
		}
		return s, nil
	})
	if e != nil {
		t.Fatal("max rows", e)
	}
	after, _ := json.Marshal(base.WindowsInventory)
	if !bytes.Equal(before, after) {
		t.Fatal("base mutated")
	}
}
