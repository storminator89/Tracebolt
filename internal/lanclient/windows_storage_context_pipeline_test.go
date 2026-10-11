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
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"net/http"
	"strings"
	"testing"
	"time"
)

func storageConsentFixture(m Material) windowsstorage.Consent {
	return windowsstorage.Consent{SchemaVersion: windowsstorage.ConsentVersion, Scope: windowsstorage.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("3", 32), Enabled: true}
}
func storageSourceFixture(_ context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
	s := windowsstorage.Empty(r, windowsstorage.ErrUnavailable.Error())
	name := "demo-private-disk"
	id := "0"
	health := uint16(0)
	bus := uint16(17)
	media := uint16(4)
	size := "1000000000"
	guid := `\\?\Volume{11111111-1111-1111-1111-111111111111}\`
	s.Drives = windowsstorage.Drives{Quality: "observed", Rows: []windowsstorage.Drive{{Letter: "C:", DriveType: "fixed", VolumeGUID: &guid, Quality: "observed"}}, ObservedCount: 1, CountExact: true, Complete: true}
	s.Disks = windowsstorage.Disks{Quality: "observed", Rows: []windowsstorage.Disk{{Index: 0, DeviceID: windowsstorage.Field{Value: &id, Quality: "observed"}, FriendlyName: windowsstorage.Field{Value: &name, Quality: "observed"}, HealthStatus: &health, OperationalStatus: []uint16{2}, BusType: &bus, MediaType: &media, SizeBytes: &size}}, ObservedCount: 1, CountExact: true, Complete: true}
	return s, nil
}

func runStorageOnly(ctx context.Context, m Material, s *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowsstorage.Consent, bool), collect storageContextCollector) (Report, error) {
	return runUsingStateWithStorageContextAuthorityDependencies(ctx, m, s, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect, func() bool { return true })
}
func TestWindowsStorageEndToEndPrivateAuthority(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", transport)
			state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			c := storageConsentFixture(f.material)
			calls := 0
			send := func(req *http.Request) (*http.Response, error) { return startupServe(t, f, req), nil }
			read := func() (windowsstorage.Consent, bool) { return c, c.Enabled }
			collect := func(ctx context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
				calls++
				return storageSourceFixture(ctx, r)
			}
			c.Enabled = false
			if _, e := runStorageOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			if calls != 0 || f.view(t, time.Now().UTC()).StorageContext != nil {
				t.Fatal("default off")
			}
			c.Enabled = true
			if _, e := runStorageOnly(context.Background(), f.material, state, send, read, collect); e != nil {
				t.Fatal(e)
			}
			v := f.view(t, time.Now().UTC())
			if calls != 1 || v.StorageContext == nil || *v.StorageContext.Disks.Rows[0].FriendlyName.Value != "demo-private-disk" {
				t.Fatal("source lost")
			}
			basic, e := f.store.LatestObservations(context.Background())
			b, _ := json.Marshal(basic)
			if e != nil || bytes.Contains(b, []byte("demo-private-disk")) || bytes.Contains(b, []byte("storageContext")) {
				t.Fatal("private export")
			}
			expired, e := v.RecheckAt(v.Snapshot.CollectedAt.Add(24 * time.Hour))
			if e != nil || expired.StorageContext != nil {
				t.Fatal("expiry")
			}
			v.Status = "revoked"
			revoked, e := v.RecheckAt(v.ServerNow)
			if e != nil || revoked.StorageContext != nil {
				t.Fatal("revocation")
			}
		})
	}
}
func TestWindowsStorageRetryAndRevocation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "http-test")
	state, e := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { state.Close() }()
	c := storageConsentFixture(f.material)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runStorageOnly(context.Background(), f.material, state, func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			bodies = append(bodies, bytes.Clone(b))
			req.Body = io.NopCloser(bytes.NewReader(b))
			response := startupServe(t, f, req)
			if len(bodies) == 1 {
				response.Body.Close()
				return nil, errors.New("lost fixture response")
			}
			return response, nil
		}, func() (windowsstorage.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
			calls++
			return storageSourceFixture(ctx, r)
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
	if !after.StorageContext.CollectedAt.Equal(before.StorageContext.CollectedAt) {
		t.Fatal("age refreshed")
	}
	sent := false
	_, e = runStorageOnly(context.Background(), f.material, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowsstorage.Consent, bool) { return c, c.Enabled }, func(ctx context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
		s, e := storageSourceFixture(ctx, r)
		c.Enabled = false
		return s, e
	})
	if e == nil || sent {
		t.Fatal("revoked source sent")
	}
}
func TestWindowsStorageFrameVersionsBindingAndBounds(t *testing.T) {
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
	good, raw, e := appendWindowsStorageContext(ctx, m, base, storageConsentFixture(m), storageSourceFixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-wire", "missing", "generation", "capture", "duplicate-grant", "extra", "false-mapping"} {
		copy := good
		s := *good.WindowsStorageContext
		copy.WindowsStorageContext = &s
		switch kind {
		case "old-wire":
			copy.SchemaVersion = FrameWindowsSessionContextVersion
		case "missing":
			copy.WindowsStorageContext = nil
		case "generation":
			s.GenerationID = "sample_" + strings.Repeat("7", 32)
		case "capture":
			s.CollectedAt = s.CollectedAt.Add(-time.Second)
		case "duplicate-grant":
			s.GrantID = copy.WindowsSessionContext.GrantID
		case "false-mapping":
			s.Drives.Rows = append([]windowsstorage.Drive{}, s.Drives.Rows...)
			s.Drives.Rows[0].VolumeGUID = nil
		}
		bad, _ := json.Marshal(copy)
		if kind == "extra" {
			bad = bytes.Replace(bad, []byte(`"disks":`), []byte(`"serialNumber":"private","disks":`), 1)
		}
		if _, e = decodeFrameForConfig(bad, 1, m.config); e == nil {
			t.Fatal("sender admitted", kind)
		}
		if _, e = lanstore.ValidateFrame(bad, time.Now().UTC()); e == nil {
			t.Fatal("manager admitted", kind)
		}
	}
}
func TestWindowsStorageOptionalBudgetPreservesBase(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	c := storageConsentFixture(m)
	ctx := context.WithValue(context.Background(), patchBudgetKey{}, patchSourceBudget{15 * time.Millisecond, 40 * time.Millisecond})
	var sent frame
	_, e = runStorageOnly(ctx, m, state, func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&sent)
		return nil, errors.New("fixture offline")
	}, func() (windowsstorage.Consent, bool) { return c, true }, func(ctx context.Context, _ windowsstorage.Request) (windowsstorage.Snapshot, error) {
		<-ctx.Done()
		return windowsstorage.Snapshot{}, ctx.Err()
	})
	if !errors.Is(e, ErrTransport) || sent.WindowsInventory == nil || sent.WindowsStorageContext == nil || sent.WindowsStorageContext.Disks.Reason != windowsstorage.ErrBudget.Error() {
		t.Fatal("optional source suppressed base", e)
	}
}

func TestWindowsStorageFrameBudgetPreservesAllScopesBaseAndSelf(t *testing.T) {
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
	f.Observation.Privacy = []string{strings.Repeat("a", 2250), strings.Repeat("b", 2250), strings.Repeat("c", 2250)}
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
	f, _, err = appendWindowsPatchContext(ctx, m, f, patchConsentFixture(m), patchSourceFixture)
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
	f, raw, err = appendWindowsHardwareContext(ctx, m, f, hardwareConsentFixture(m), hardwareSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err = appendWindowsStorageContext(ctx, m, f, storageConsentFixture(m), storageSourceFixture)
	if err != nil {
		t.Fatal(err)
	}
	if f.WindowsStorageContext == nil || f.WindowsHardwareContext == nil {
		t.Fatal("storage envelope omitted")
	}
	if f.WindowsUpdates == nil || f.WindowsPatchContext == nil || f.WindowsSecurityPosture == nil || f.WindowsSessionContext == nil {
		t.Fatal("frame fitting omitted a granted context envelope")
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

func TestWindowsStoragePendingReplacementAndDisableNeverReuseGrant(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	consent := storageConsentFixture(m)
	calls := 0
	var bodies [][]byte
	run := func() (Report, error) {
		return runStorageOnly(context.Background(), m, state, func(req *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(req.Body)
			bodies = append(bodies, raw)
			return nil, errors.New("fixture no receiver")
		}, func() (windowsstorage.Consent, bool) { return consent, consent.Enabled }, func(ctx context.Context, r windowsstorage.Request) (windowsstorage.Snapshot, error) {
			calls++
			return storageSourceFixture(ctx, r)
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
	if current.WindowsStorageContext == nil || current.WindowsStorageContext.GrantID != consent.GrantID || current.Sequence <= 1 || bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("replacement scope lost floor")
	}
	consent.Enabled = false
	if r, e := run(); !errors.Is(e, ErrTransport) || r.RetriedPending || calls != 2 {
		t.Fatal("disabled pending reused", r, e)
	}
	var disabled frame
	json.Unmarshal(bodies[2], &disabled)
	if disabled.WindowsStorageContext != nil || disabled.SchemaVersion != FrameWindowsInventoryVersion || disabled.Sequence <= current.Sequence {
		t.Fatal("disable reset or sent storage")
	}
}
