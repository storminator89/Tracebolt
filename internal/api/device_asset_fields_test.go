package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
)

func installDeviceAssetFieldsFixture(t *testing.T, o operatorFixture) (*fixtureMonitoringSource, string) {
	t.Helper()
	f := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	return f, "/api/devices/" + f.inputs[0].DeviceID + "/asset-fields"
}
func readDeviceAssetFieldsFixture(t *testing.T, o operatorFixture, path string) deviceAssetFieldsView {
	t.Helper()
	r, value := o.call(t, http.MethodGet, path, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatalf("read %d: %v", r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var view deviceAssetFieldsView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view
}
func deviceAssetFieldsBody(v deviceAssetFieldsView, ordinal string) map[string]any {
	return map[string]any{"binding": v.Binding, "validUntil": v.ValidUntil, "expectedRevision": v.Revision, "operationId": "assetop_" + strings.Repeat(ordinal, 32), "fields": store.DeviceAssetValues{AssetTag: "<img src=x onerror=alert(1)>", Location: "fixture handover", WarrantyEnd: "2028-02-29"}}
}

func TestDeviceAssetFieldsPrivateJournalRoundTripAndUncertainReceipt(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read", r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	view := readDeviceAssetFieldsFixture(t, o, path)
	if view.Revision != 0 || !view.CanWrite || view.Fields != (store.DeviceAssetValues{}) || len(view.Operations) != 0 || view.ValidUntil.Sub(view.ServerNow) > 60*time.Second {
		t.Fatal("initial view", view)
	}
	body := deviceAssetFieldsBody(view, "1")
	if r, _ := o.call(t, "POST", path, body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", path, body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("foreign origin", r.StatusCode)
	}
	if r, value := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 {
		t.Fatal("add", r.StatusCode, value)
	}
	saved := readDeviceAssetFieldsFixture(t, o, path)
	if saved.Revision != 1 || saved.Fields != body["fields"] || saved.Operations[0].ID != body["operationId"] {
		t.Fatal("save/receipt", saved)
	}
	// A deliberate exact replay is idempotent, but clients use GET receipts after
	// uncertainty and never automatically replay a write.
	if r, v := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 || v["revision"] != float64(1) {
		t.Fatal("duplicate", r.StatusCode, v)
	}
	changed := deviceAssetFieldsBody(view, "1")
	changed["fields"] = store.DeviceAssetValues{AssetTag: "different"}
	if r, _ := o.call(t, "POST", path, changed, csrf, nil); r.StatusCode != 409 {
		t.Fatal("changed replay", r.StatusCode)
	}
	stale := deviceAssetFieldsBody(view, "2")
	if r, _ := o.call(t, "POST", path, stale, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision", r.StatusCode)
	}
	currentSave := readDeviceAssetFieldsFixture(t, o, path)
	clearBody := deviceAssetFieldsBody(currentSave, "3")
	clearBody["fields"] = store.DeviceAssetValues{}
	if r, v := o.call(t, "POST", path, clearBody, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	if got := readDeviceAssetFieldsFixture(t, o, path); got.Fields != (store.DeviceAssetValues{}) || got.Revision != 2 {
		t.Fatal(got)
	}

	current := readDeviceAssetFieldsFixture(t, o, path)
	raw, _ := json.Marshal(current)
	for _, private := range []string{"requestDigest", "invitation", "certificateHash", f.inputs[0].CertificateHash, "fixture-csrf", o.app.csrf} {
		if private != "" && strings.Contains(string(raw), private) {
			t.Fatal("private binding leaked")
		}
	}
	for _, p := range []string{"/api/overview", "/api/devices", "/api/cases"} {
		_, v := o.call(t, "GET", p, nil, "", nil)
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "fixture handover") {
			t.Fatal("note escaped private resource", p)
		}
	}
	if f.leases < 8 {
		t.Fatal("reads and writes lacked source lease", f.leases)
	}
}

func TestDeviceAssetFieldsNamedReadOnlyAndStrictRoutes(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, path := installDeviceAssetFieldsFixture(t, o)
	r, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, login)
	}
	v := readDeviceAssetFieldsFixture(t, o, path)
	if v.CanWrite {
		t.Fatal("named writer")
	}
	if r, _ := o.call(t, "POST", path, deviceAssetFieldsBody(v, "1"), login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named post", r.StatusCode)
	}
	for _, p := range []string{path + "/", path + "?text=secret", path + "?", strings.Replace(path, "agent_", "wrong_", 1)} {
		if r, _ := o.call(t, "GET", p, nil, "", nil); r.StatusCode == 200 {
			t.Fatal("route accepted", p)
		}
	}
	if r, _ := o.call(t, "DELETE", path, nil, "", nil); r.StatusCode != 403 {
		t.Fatal("named deletion should be denied", r.StatusCode)
	}
}

func TestDeviceAssetFieldsIdentityRenewalReplacementAndSessionBinding(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := readDeviceAssetFieldsFixture(t, o, path)
	body := deviceAssetFieldsBody(before, "1")
	if r, v := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	// Renewal retains original identity; neither a changed display name nor a
	// fresh leaf may migrate the notebook onto a replacement original identity.
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	f.devices[0].AgentCertificate.ExpiresAt = &f.inputs[0].AuthorityUntil
	f.devices[0].Name = "Renamed display"
	if v := readDeviceAssetFieldsFixture(t, o, path); v.Revision != 1 || v.IdentityKey != before.IdentityKey {
		t.Fatal("renewal lost notes")
	}
	f.inputs[0].CertificateHash = strings.Repeat("d", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	if v := readDeviceAssetFieldsFixture(t, o, path); v.Revision != 0 || v.Fields != (store.DeviceAssetValues{}) || v.IdentityKey == before.IdentityKey {
		t.Fatal("replacement inherited notes")
	}
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("old identity token accepted", r.StatusCode)
	}
	newView := readDeviceAssetFieldsFixture(t, o, path)
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("logout", r.StatusCode)
	}
	_, login = o.login(t)
	csrf = login["csrfToken"].(string)
	if r, _ := o.call(t, "POST", path, deviceAssetFieldsBody(newView, "2"), csrf, nil); r.StatusCode != 409 {
		t.Fatal("old session token accepted", r.StatusCode)
	}
}

func TestDeviceAssetFieldsCommittedThenFinalGuardIsUnconfirmedAndReconciles(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceAssetFieldsFixture(t, o, path)
	body := deviceAssetFieldsBody(v, "5")
	f.onGuard = func(n int) {
		if n == 5 {
			f.inputs[0].Authorized = false
		}
	}
	r, result := o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 503 || result["error"].(map[string]any)["code"] != "device_asset_fields_unconfirmed" {
		t.Fatal("committed write presented as rejected", r.StatusCode, result)
	}
	f.onGuard = nil
	f.inputs[0].Authorized = true
	saved := readDeviceAssetFieldsFixture(t, o, path)
	if saved.Revision != 1 || len(saved.Operations) != 1 || saved.Operations[0].ID != body["operationId"] {
		t.Fatal("lost durable reconciliation", saved)
	}
}

func TestDeviceAssetFieldsWorstCaseEscapedResponseFitsPrivateBound(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	o.login(t)
	manager, now, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if err != nil {
		t.Fatal(err)
	}
	id := f.inputs[0].DeviceID
	for i := 1; i <= 100; i++ {
		_, err = o.app.store.ApplyDeviceAssetFields(context.Background(), manager, devices[id].identity, id, fmt.Sprintf("assetop_%032x", i), store.DeviceAssetValues{AssetTag: strings.Repeat("<", 80), Location: strings.Repeat("<", 160)}, uint64(i-1), now, func() error { return nil })
		if err != nil {
			t.Fatal(i, err)
		}
	}
	v := readDeviceAssetFieldsFixture(t, o, path)
	raw, _ := json.Marshal(v)
	if len(v.Operations) != 100 || len(raw) >= deviceAssetFieldsResponseBytes {
		t.Fatal(len(raw))
	}
}

func TestDeviceAssetFieldsReadRefusesRetainedFutureTimestamps(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceAssetFieldsFixture(t, o, path)
	if r, result := o.call(t, "POST", path, deviceAssetFieldsBody(v, "6"), csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, result)
	}
	f.now = f.now.Add(-time.Second)
	if r, result := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 503 {
		t.Fatal("future note exposed", r.StatusCode, result)
	}
}

func TestDeviceAssetFieldsNegativeReadFloorRejectsRollbackAcrossHandlers(t *testing.T) {
	for _, otherHandler := range []bool{false, true} {
		t.Run(fmt.Sprint(otherHandler), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			f, path := installDeviceAssetFieldsFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceAssetFieldsFixture(t, o, path)
			body := deviceAssetFieldsBody(v, "7")
			original := f.now
			f.now = v.ValidUntil
			negative := readDeviceAssetFieldsFixture(t, o, path)
			if negative.ServerNow.Before(v.ValidUntil) || negative.Revision != 0 || len(negative.Operations) != 0 {
				t.Fatal("not a negative terminal read")
			}
			if otherHandler {
				first := o.server.Config.Handler.(*operatorHandler)
				o.server.Config.Handler = &operatorHandler{
					app: first.app, auth: first.auth, registry: first.registry,
					origin: first.origin, authority: first.authority, cookieName: first.cookieName,
					insecureHTTPTest: first.insecureHTTPTest, fleetGroupSources: first.fleetGroupSources,
				}
			}
			f.now = original
			if r, result := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 || result["error"].(map[string]any)["code"] != "device_asset_fields_rejected" {
				t.Fatal("rollback reopened original review", r.StatusCode, result)
			}
			f.now = v.ValidUntil
			if got := readDeviceAssetFieldsFixture(t, o, path); got.Revision != 0 {
				t.Fatal("late write committed")
			}
		})
	}
}

func TestDeviceAssetFieldsNewSigningKeyRejectsOldReviewWithResetClockFloor(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceAssetFieldsFixture(t, o, path)
	body := deviceAssetFieldsBody(v, "8")
	h := o.server.Config.Handler.(*operatorHandler)
	fresh, err := New(o.app.store, o.app.port, o.app.web, o.app.sampleDevice())
	if err != nil || fresh.csrf == o.app.csrf {
		t.Fatal("new process signing key", err)
	}
	h.app = fresh // retain old auth only to isolate key-epoch rejection in this test
	if r, result := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 || result["error"].(map[string]any)["code"] != "device_asset_fields_rejected" {
		t.Fatal("old key review accepted", r.StatusCode, result)
	}
	if current := readDeviceAssetFieldsFixture(t, o, path); current.Revision != 0 || current.IdentityKey != v.IdentityKey {
		t.Fatal("restart changed original journal identity")
	}
	_ = f
}

// A controllable, serialized source lease mirrors the production enrollment
// BEGIN IMMEDIATE ordering without touching enrollment or executing an endpoint.
type serializedDeviceAssetFieldsSource struct {
	*fixtureMonitoringSource
	leaseMu     sync.Mutex
	clock       atomic.Int64
	guardHook   func(int)
	beforeLease func(int64)
	leaseCalls  atomic.Int64
}

func (f *serializedDeviceAssetFieldsSource) Now() time.Time {
	return time.Unix(0, f.clock.Load()).UTC()
}
func (f *serializedDeviceAssetFieldsSource) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, fn func(func(time.Time) error) error) error {
	ordinal := f.leaseCalls.Add(1)
	if f.beforeLease != nil {
		f.beforeLease(ordinal)
	}
	f.leaseMu.Lock()
	defer f.leaseMu.Unlock()
	calls := 0
	return fn(func(min time.Time) error {
		calls++
		if f.guardHook != nil {
			f.guardHook(calls)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		at := f.Now()
		if at.Before(min) {
			return fmt.Errorf("clock rollback")
		}
		for _, in := range expected {
			if !in.Authorized || !at.Before(in.AuthorityUntil) {
				return fmt.Errorf("authority expired")
			}
		}
		return nil
	})
}
func installSerializedDeviceAssetFields(t *testing.T, o operatorFixture) (*serializedDeviceAssetFieldsSource, string) {
	t.Helper()
	f, path := installDeviceAssetFieldsFixture(t, o)
	s := &serializedDeviceAssetFieldsSource{fixtureMonitoringSource: f}
	s.clock.Store(f.now.UnixNano())
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{s}
	return s, path
}

func TestDeviceAssetFieldsNegativeReadWaitsForAdmittedWriter(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%v", commit), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			s, path := installSerializedDeviceAssetFields(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceAssetFieldsFixture(t, o, path)
			body := deviceAssetFieldsBody(v, "9")
			s.clock.Store(v.ValidUntil.Add(-time.Second).UnixNano())
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			// This fixture calls guard1 at handler entry, guard2 before SQL write,
			// guard3 precommit, guard4 after the store transaction has committed.
			point := 2
			if commit {
				point = 4
			}
			s.guardHook = func(n int) {
				if n == point {
					once.Do(func() { close(entered); <-release })
				}
			}
			writeDone := make(chan int, 1)
			go func() { r, _ := o.call(t, "POST", path, body, csrf, nil); writeDone <- r.StatusCode }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("writer did not enter lease")
			}
			s.clock.Store(v.ValidUntil.UnixNano())
			readDone := make(chan map[string]any, 1)
			go func() {
				r, value := o.call(t, "GET", path, nil, "", nil)
				if r.StatusCode != 200 {
					value["status"] = r.StatusCode
				}
				readDone <- value
			}()
			select {
			case result := <-readDone:
				close(release)
				t.Fatal("read crossed active writer lease", result)
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			select {
			case <-writeDone:
			case <-time.After(3 * time.Second):
				t.Fatal("writer did not settle")
			}
			var result map[string]any
			select {
			case result = <-readDone:
			case <-time.After(3 * time.Second):
				t.Fatal("read did not settle")
			}
			want := float64(0)
			if commit {
				want = 1
			}
			if result["revision"] != want || result["status"] != nil {
				t.Fatal("negative read lost committed receipt or invented one", result)
			}
		})
	}
}

func TestDeviceAssetFieldsDelayedWriterLosesToTerminalRead(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	s, path := installSerializedDeviceAssetFields(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceAssetFieldsFixture(t, o, path)
	body := deviceAssetFieldsBody(v, "a")
	s.clock.Store(v.ValidUntil.Add(-time.Second).UnixNano())
	entered, release := make(chan struct{}), make(chan struct{})
	s.beforeLease = func(n int64) {
		if n == 2 {
			close(entered)
			<-release
		}
	}
	done := make(chan int, 1)
	go func() { r, _ := o.call(t, "POST", path, body, csrf, nil); done <- r.StatusCode }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("writer never reached lease")
	}
	s.clock.Store(v.ValidUntil.UnixNano())
	negative := readDeviceAssetFieldsFixture(t, o, path)
	if negative.Revision != 0 {
		t.Fatal("unexpected receipt")
	}
	s.clock.Store(v.ValidUntil.Add(-time.Second).UnixNano())
	close(release)
	select {
	case status := <-done:
		if status != 409 {
			t.Fatal("deferred writer accepted", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not settle")
	}
	s.clock.Store(v.ValidUntil.UnixNano())
	if current := readDeviceAssetFieldsFixture(t, o, path); current.Revision != 0 {
		t.Fatal("late commit after terminal read")
	}
}

func TestDeviceAssetFieldsSameTimeConcurrentReads(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, path := installSerializedDeviceAssetFields(t, o)
	o.login(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := o.call(t, "GET", path, nil, "", nil)
			if r.StatusCode != 200 {
				t.Errorf("concurrent read %d", r.StatusCode)
			}
		}()
	}
	wg.Wait()
}

func TestDeviceAssetFieldsExpiryAndFinalAuthorityFailureAreClosed(t *testing.T) {
	for _, kind := range []string{"expiry", "revoke", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			f, path := installDeviceAssetFieldsFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceAssetFieldsFixture(t, o, path)
			body := deviceAssetFieldsBody(v, "1")
			manager, _, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
			if err != nil {
				t.Fatal(err)
			}
			identity := devices[f.inputs[0].DeviceID].identity
			if kind == "expiry" {
				f.now = v.ValidUntil
			} else {
				f.onGuard = func(n int) {
					if n == 3 {
						if kind == "revoke" {
							f.inputs[0].Authorized = false
						} else {
							f.now = f.now.Add(-time.Second)
						}
					}
				}
			}
			if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode == 200 {
				t.Fatal("unsafe save")
			}
			stored, err := o.app.store.ReadDeviceAssetFields(context.Background(), manager, identity, f.inputs[0].DeviceID)
			if err != nil || stored.Revision != 0 {
				t.Fatal("failed final guard changed asset fields", stored, err)
			}
		})
	}
}

func TestDeviceAssetFieldsInputAndPlatformBounds(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceAssetFieldsFixture(t, o, path)
	for _, fields := range []json.RawMessage{
		json.RawMessage(`{"assetTag":" padded ","location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":"x\u202e","location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":"x\u0000","location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":"x\ud800","location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":"","location":"","warrantyEnd":"2026-02-29"}`),
		json.RawMessage(`{"assetTag":"","location":""}`),
		json.RawMessage(`{"assetTag":"","location":"","warrantyEnd":"","extra":true}`),
		json.RawMessage(`{"assetTag":"","assetTag":"other","location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":null,"location":"","warrantyEnd":""}`),
		json.RawMessage(`{"assetTag":3,"location":"","warrantyEnd":""}`),
		json.RawMessage(`null`), json.RawMessage(`[]`),
	} {
		body := deviceAssetFieldsBody(v, "1")
		body["fields"] = fields
		if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
			t.Fatal("invalid nested fields", string(fields), r.StatusCode)
		}
	}

	body := deviceAssetFieldsBody(v, "1")
	body["extra"] = true
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("unknown field", r.StatusCode)
	}
	f.snapshots[0].Platform = "linux"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 404 {
		t.Fatal("unsupported platform", r.StatusCode)
	}
}

func TestDeviceAssetFieldsReadRejectsFutureStoredTimestampAfterRestart(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceAssetFieldsFixture(t, o)
	o.login(t)
	manager, now, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if err != nil {
		t.Fatal(err)
	}
	id := f.inputs[0].DeviceID
	_, err = o.app.store.ApplyDeviceAssetFields(context.Background(), manager, devices[id].identity, id, "assetop_"+strings.Repeat("1", 32), store.DeviceAssetValues{AssetTag: "future"}, 0, now.Add(time.Second), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// No view has advanced the in-memory floor. Retained authored time still closes reads.
	if r, value := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 503 {
		t.Fatal(r.StatusCode, value)
	}
}
