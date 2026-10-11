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
	"localrmm/internal/windowsresourcecontext"
	"net/http"
	"strings"
	"testing"
	"time"
)

func resourceConsentFixture(m Material) windowsresourcecontext.Consent {
	return windowsresourcecontext.Consent{SchemaVersion: windowsresourcecontext.ConsentVersion, Scope: windowsresourcecontext.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("0", 32), Enabled: true}
}
func resourceSourceFixture(_ context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
	s := windowsresourcecontext.Empty(r, windowsresourcecontext.ErrUnavailable.Error())
	label, arch := "demo-private-CPU", "x64"
	n := uint32(8)
	s.Processors = windowsresourcecontext.Processors{Quality: "observed", Source: "Win32_Processor", Rows: []windowsresourcecontext.Processor{{Name: windowsresourcecontext.Field{Value: &label, Quality: "observed"}, Architecture: windowsresourcecontext.Field{Value: &arch, Quality: "observed"}, Cores: windowsresourcecontext.CountField{Value: &n, Quality: "observed"}, LogicalProcessors: windowsresourcecontext.CountField{Value: &n, Quality: "observed"}}}, TotalCores: &n, TotalLogicalProcessors: &n}
	installed := "17179869184"
	s.InstalledMemory = windowsresourcecontext.InstalledMemory{Quality: "observed", Source: "GetPhysicallyInstalledSystemMemory", InstalledBytes: &installed}
	return s, windowsresourcecontext.Validate(s)
}

func runResourceContextOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowsresourcecontext.Consent, bool), collect resourceContextCollector) (Report, error) {
	return runUsingStateWithResourceContextAuthorityDependencies(ctx, m, s, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect, func() bool { return true })
}
func TestWindowsResourceContextEndToEndPrivateAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			c := resourceConsentFixture(f.material)
			calls := 0
			send := func(req *http.Request) (*http.Response, error) { return startupServe(t, f, req), nil }
			read := func() (windowsresourcecontext.Consent, bool) { return c, c.Enabled }
			collect := func(ctx context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
				calls++
				return resourceSourceFixture(ctx, r)
			}
			c.Enabled = false
			if _, e := runResourceContextOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			if calls != 0 || f.view(t, time.Now().UTC()).ResourceContext != nil {
				t.Fatal("default off")
			}
			c.Enabled = true
			if _, e := runResourceContextOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			v := f.view(t, time.Now().UTC())
			if calls != 1 || v.ResourceContext == nil || *v.ResourceContext.Processors.Rows[0].Name.Value != "demo-private-CPU" {
				t.Fatal("source lost")
			}
			basic, e := f.store.LatestObservations(context.Background())
			b, _ := json.Marshal(basic)
			if e != nil || bytes.Contains(b, []byte("demo-private-CPU")) || bytes.Contains(b, []byte("resourceContext")) {
				t.Fatal("private export")
			}
			expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
			if e != nil || expired.ResourceContext != nil {
				t.Fatal("expiry")
			}
			v.Status = "revoked"
			revoked, e := v.RecheckAt(v.ServerNow)
			if e != nil || revoked.ResourceContext != nil {
				t.Fatal("revocation")
			}
		})
	}
}
func TestWindowsResourceContextRetryAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := resourceConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runResourceContextOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(b))
			req.Body = io.NopCloser(bytes.NewReader(b))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("lost fixture response")
			}
			return response, nil
		}, func() (windowsresourcecontext.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
			calls++
			return resourceSourceFixture(ctx, r)
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
	if !after.ResourceContext.CollectedAt.Equal(before.ResourceContext.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runResourceContextOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowsresourcecontext.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
		s, e := resourceSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked source sent")
	}
}
func TestWindowsResourceContextFrameVersionsBindingAndBounds(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := context.Background()
	base, _, e := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	base, _, e = appendWindowsSessionContext(ctx, m, base, sessionConsentFixture(m), sessionSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	good, raw, e := appendWindowsResourceContext(ctx, m, base, resourceConsentFixture(m), resourceSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "generation", "capture", "duplicate-grant", "extra", "false-status"} {
		copy := good
		s := *good.WindowsResourceContext
		copy.WindowsResourceContext = &s
		switch kind {
		case "old-wire":
			copy.SchemaVersion = FrameWindowsSessionContextVersion
		case "missing":
			copy.WindowsResourceContext = nil
		case "generation":
			s.GenerationID = "sample_" + strings.Repeat("7", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			s.GrantID = copy.WindowsSessionContext.GrantID
		case "false-status":
			s.Memory.Quality = "healthy"

		}
		bad, _ := json.Marshal(copy)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"pagefiles":`), []byte(`"path":"private","pagefiles":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
}
func TestWindowsResourceContextOptionalBudgetPreservesBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := resourceConsentFixture(m)
	ctx := context.WithValue(context.Background(), patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	var sent frame
	_, e = runResourceContextOnly(ctx, m, state, func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}, func() (windowsresourcecontext.Consent, bool) { return c, true }, func(ctx context.Context, _ windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
		<-ctx.Done()
		return windowsresourcecontext.Snapshot{}, ctx.Err()
	})
	if !errors.Is(e, ErrTransport) || sent.WindowsInventory == nil || sent.WindowsResourceContext == nil || sent.WindowsResourceContext.Memory.Reason != windowsresourcecontext.ErrBudget.Error() {
		t.Fatal("optional source suppressed base", e)
	}
}

func TestWindowsResourceContextPendingReplacementAndDisableNeverReuseGrant(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	consent := resourceConsentFixture(m)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runResourceContextOnly(context.Background(), m, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, raw)
			return nil, errors.New("fixture no receiver")
		}, func() (windowsresourcecontext.Consent, bool) { return consent, consent.Enabled }, func(ctx context.Context, r windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
			calls++
			return resourceSourceFixture(ctx, r)
		})
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	consent.GrantID = strings.Repeat("2", 32)
	if r, e := run(); !errors.Is(e, ErrTransport) || r.RetriedPending || calls != 2 {
		t.Fatal("old pending reused", r, e, calls)
	}
	var current frame
	json.Unmarshal(bodies[1], &current)
	if current.WindowsResourceContext == nil || current.WindowsResourceContext.GrantID != consent.GrantID || current.Sequence <= 1 || bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("replacement scope lost floor")
	}
	consent.Enabled = false
	if r, e := run(); !errors.Is(e, ErrTransport) || r.RetriedPending || calls != 2 {
		t.Fatal("disabled pending reused", r, e)
	}
	var disabled frame
	json.Unmarshal(bodies[2], &disabled)
	if disabled.WindowsResourceContext != nil || disabled.SchemaVersion != FrameWindowsInventoryVersion || disabled.Sequence <= current.Sequence {
		t.Fatal("disable reset or sent security coverage")
	}
}
