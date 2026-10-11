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
	"localrmm/internal/model"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsstorageio"
	"net/http"
	"strings"
	"testing"
	"time"
)

func storageIOConsentFixture(m Material) windowsstorageio.Consent {
	return windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("2", 32), Enabled: true}
}
func storageIOSourceFixture(_ context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
	s := windowsstorageio.Empty(r, windowsstorageio.ErrUnavailable.Error())
	start, end, interval := r.CollectedAt, r.CollectedAt.Add(time.Second), uint64(1000)
	value := 4096.5
	metric := windowsstorageio.Metric{Value: &value, Quality: "observed"}
	s.PerfDisk = windowsstorageio.PerfDisk{Quality: "observed", Source: "PDH PhysicalDisk(_Total)", SampleStartedAt: &start, SampleEndedAt: &end, IntervalMilliseconds: &interval, ReadBytesPerSecond: metric, WriteBytesPerSecond: metric, ReadOperationsPerSecond: metric, WriteOperationsPerSecond: metric, ReadLatencySeconds: metric, WriteLatencySeconds: metric, AverageQueueLength: metric, CurrentQueueLength: metric}
	return s, windowsstorageio.Validate(s)
}
func storageIOWindowsSource(_ context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
	return windowsmanaged.FromReport(syntheticWindowsReport(time.Now().UTC().Add(-2*time.Second)), generation)
}

func runStorageIOOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowsstorageio.Consent, bool), collect storageIOCollector) (Report, error) {
	return runUsingStateWithStorageIOAuthorityDependencies(ctx, m, s, nil, nil, nil, storageIOWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect, func() bool { return true })
}
func TestWindowsStorageIOEndToEndPrivateAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			c := storageIOConsentFixture(f.material)
			calls := 0
			send := func(req *http.Request) (*http.Response, error) { return startupServe(t, f, req), nil }
			read := func() (windowsstorageio.Consent, bool) { return c, c.Enabled }
			collect := func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
				calls++
				return storageIOSourceFixture(ctx, r)
			}
			c.Enabled = false
			if _, e := runStorageIOOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			if calls != 0 || f.view(t, time.Now().UTC()).StorageIO != nil {
				t.Fatal("default off")
			}
			c.Enabled = true
			if _, e := runStorageIOOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			v := f.view(t, time.Now().UTC())
			if calls != 1 || v.StorageIO == nil || *v.StorageIO.PerfDisk.ReadBytesPerSecond.Value != 4096.5 {
				t.Fatal("source lost")
			}
			basic, e := f.store.LatestObservations(context.Background())
			b, _ := json.Marshal(basic)
			if e != nil || bytes.Contains(b, []byte("PerfDisk")) || bytes.Contains(b, []byte("storageIO")) {
				t.Fatal("private export")
			}
			expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
			if e != nil || expired.StorageIO != nil {
				t.Fatal("expiry")
			}
			v.Status = "revoked"
			revoked, e := v.RecheckAt(v.ServerNow)
			if e != nil || revoked.StorageIO != nil {
				t.Fatal("revocation")
			}
		})
	}
}
func TestWindowsStorageIORetryAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := storageIOConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runStorageIOOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(b))
			req.Body = io.NopCloser(bytes.NewReader(b))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("lost fixture response")
			}
			return response, nil
		}, func() (windowsstorageio.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
			calls++
			return storageIOSourceFixture(ctx, r)
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
	if !after.StorageIO.CollectedAt.Equal(before.StorageIO.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runStorageIOOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowsstorageio.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
		s, e := storageIOSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked source sent")
	}
}
func TestWindowsStorageIOFrameVersionsBindingAndBounds(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	ctx := context.Background()
	base, _, e := collectWindowsFrame(ctx, m.config, 1, storageIOWindowsSource)
	if e != nil {
		t.Fatal(e)
	}
	base, _, e = appendWindowsSessionContext(ctx, m, base, sessionConsentFixture(m), sessionSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	good, raw, e := appendWindowsStorageIO(ctx, m, base, storageIOConsentFixture(m), storageIOSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "generation", "capture", "duplicate-grant", "extra", "false-status", "future-sample"} {
		copy := good
		s := *good.WindowsStorageIO
		copy.WindowsStorageIO = &s
		switch kind {
		case "old-wire":
			copy.SchemaVersion = FrameWindowsSessionContextVersion
		case "missing":
			copy.WindowsStorageIO = nil
		case "generation":
			s.GenerationID = "sample_" + strings.Repeat("7", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			s.GrantID = copy.WindowsSessionContext.GrantID
		case "future-sample":
			future := copy.Observation.GeneratedAt.Add(time.Second)
			s.PerfDisk.SampleEndedAt = &future
		case "false-status":
			s.PerfDisk.Quality = "healthy"

		}
		bad, _ := json.Marshal(copy)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"perfDisk":`), []byte(`"path":"private","perfDisk":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
}
func TestWindowsStorageIOOptionalBudgetPreservesBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := storageIOConsentFixture(m)
	ctx := context.WithValue(context.Background(), patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	var sent frame
	_, e = runStorageIOOnly(ctx, m, state, func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}, func() (windowsstorageio.Consent, bool) { return c, true }, func(ctx context.Context, _ windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
		<-ctx.Done()
		return windowsstorageio.Snapshot{}, ctx.Err()
	})
	if !errors.Is(e, ErrTransport) || sent.WindowsInventory == nil || sent.WindowsStorageIO == nil || sent.WindowsStorageIO.PerfDisk.Reason != windowsstorageio.ErrBudget.Error() {
		t.Fatal("optional source suppressed base", e)
	}
}

func TestWindowsStorageIOPendingReplacementAndDisableNeverReuseGrant(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	consent := storageIOConsentFixture(m)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runStorageIOOnly(context.Background(), m, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, raw)
			return nil, errors.New("fixture no receiver")
		}, func() (windowsstorageio.Consent, bool) { return consent, consent.Enabled }, func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
			calls++
			return storageIOSourceFixture(ctx, r)
		})
	}
	if _, e = run(); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	consent.GrantID = strings.Repeat("ab", 16)
	if r, e := run(); !errors.Is(e, ErrTransport) || r.RetriedPending || calls != 2 {
		t.Fatal("old pending reused", r, e, calls)
	}
	var current frame
	json.Unmarshal(bodies[1], &current)
	if current.WindowsStorageIO == nil || current.WindowsStorageIO.GrantID != consent.GrantID || current.Sequence <= 1 || bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("replacement scope lost floor")
	}
	consent.Enabled = false
	if r, e := run(); !errors.Is(e, ErrTransport) || r.RetriedPending || calls != 2 {
		t.Fatal("disabled pending reused", r, e)
	}
	var disabled frame
	json.Unmarshal(bodies[2], &disabled)
	if disabled.WindowsStorageIO != nil || disabled.SchemaVersion != FrameWindowsInventoryVersion || disabled.Sequence <= current.Sequence {
		t.Fatal("disable reset or sent security coverage")
	}
}

// A standalone I/O grant must get the even-cycle first opportunity even without
// any newer context siblings. Only injected sources run; intervals are synthetic.
func TestWindowsStorageIOStandaloneRotatesBeforeSlowEarlierScope(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	calls := 0
	for cycle := 1; cycle <= 2; cycle++ {
		parent, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		ctx := context.WithValue(parent, patchBudgetKey{}, patchSourceBudget{400 * time.Millisecond, 250 * time.Millisecond})
		_, e := runUsingStateWithStorageIOAuthorityDependencies(ctx, f.material, state, nil, nil, nil, storageIOWindowsSource,
			func(req *http.Request) (*http.Response, error) {
				deadline, _ := parent.Deadline()
				if time.Until(deadline) < 100*time.Millisecond {
					t.Fatal("primary reserve consumed")
				}
				return startupServe(t, f, req), nil
			},
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			func() (windowsadapters.Consent, bool) { return adapterConsentFixture(f.material), true },
			func(ctx context.Context, _ string, _ string, _ time.Time) (windowsadapters.Snapshot, error) {
				<-ctx.Done()
				return windowsadapters.Snapshot{}, ctx.Err()
			},
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			func() (windowsstorageio.Consent, bool) { return storageIOConsentFixture(f.material), true },
			func(ctx context.Context, r windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
				calls++
				return storageIOSourceFixture(ctx, r)
			}, func() bool { return true })
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		view := f.view(t, time.Now().UTC())
		if view.StorageIO == nil {
			t.Fatal("scope silently omitted")
		}
		if cycle == 1 && (calls != 0 || view.StorageIO.PerfDisk.Reason != windowsstorageio.ErrBudget.Error()) {
			t.Fatal("odd earlier opportunity changed", calls)
		}
		if cycle == 2 && (calls != 1 || view.StorageIO.PerfDisk.ReadBytesPerSecond.Value == nil) {
			t.Fatal("standalone I/O permanently starved", calls)
		}
	}
}
