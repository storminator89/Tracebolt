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

	"localrmm/internal/windowscontact"
)

func installDeviceNotesFixture(t *testing.T, o operatorFixture) (*fixtureMonitoringSource, string) {
	t.Helper()
	f := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	return f, "/api/devices/" + f.inputs[0].DeviceID + "/handover-notes"
}
func readDeviceNotesFixture(t *testing.T, o operatorFixture, path string) deviceNotesView {
	t.Helper()
	r, value := o.call(t, http.MethodGet, path, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatalf("read %d: %v", r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var view deviceNotesView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view
}
func deviceNotesBody(v deviceNotesView, ordinal string) map[string]any {
	return map[string]any{"binding": v.Binding, "validUntil": v.ValidUntil, "expectedRevision": v.Revision, "operationId": "noteop_" + strings.Repeat(ordinal, 32), "action": "add", "noteId": "note_" + strings.Repeat(ordinal, 32), "text": "<img src=x onerror=alert(1)> fixture handover"}
}

func TestDeviceNotesPrivateJournalRoundTripAndUncertainReceipt(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read", r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	view := readDeviceNotesFixture(t, o, path)
	if view.Revision != 0 || !view.CanWrite || len(view.Notes) != 0 || len(view.Operations) != 0 || view.ValidUntil.Sub(view.ServerNow) > 60*time.Second {
		t.Fatal("initial view", view)
	}
	body := deviceNotesBody(view, "1")
	if r, _ := o.call(t, "POST", path, body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf", r.StatusCode)
	}
	if r, _ := o.call(t, "POST", path, body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("foreign origin", r.StatusCode)
	}
	if r, value := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 {
		t.Fatal("add", r.StatusCode, value)
	}
	saved := readDeviceNotesFixture(t, o, path)
	if saved.Revision != 1 || len(saved.Notes) != 1 || saved.Notes[0].Text != body["text"] || saved.Notes[0].Archived || saved.Operations[0].ID != body["operationId"] {
		t.Fatal("save/receipt", saved)
	}
	// A deliberate exact replay is idempotent, but clients use GET receipts after
	// uncertainty and never automatically replay a write.
	if r, v := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 || v["revision"] != float64(1) {
		t.Fatal("duplicate", r.StatusCode, v)
	}
	changed := deviceNotesBody(view, "1")
	changed["text"] = "different"
	if r, _ := o.call(t, "POST", path, changed, csrf, nil); r.StatusCode != 409 {
		t.Fatal("changed replay", r.StatusCode)
	}
	stale := deviceNotesBody(view, "2")
	if r, _ := o.call(t, "POST", path, stale, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision", r.StatusCode)
	}
	for i, action := range []string{"archive", "restore"} {
		current := readDeviceNotesFixture(t, o, path)
		b := deviceNotesBody(current, []string{"3", "4"}[i])
		b["action"] = action
		b["noteId"] = saved.Notes[0].ID
		b["text"] = ""
		if r, v := o.call(t, "POST", path, b, csrf, nil); r.StatusCode != 200 {
			t.Fatal(action, r.StatusCode, v)
		}
		current = readDeviceNotesFixture(t, o, path)
		if current.Notes[0].Archived != (action == "archive") || current.Notes[0].Text != saved.Notes[0].Text || current.Notes[0].CreatedAt != saved.Notes[0].CreatedAt {
			t.Fatal("archive changed original note")
		}
	}
	current := readDeviceNotesFixture(t, o, path)
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

func TestDeviceNotesNamedReadOnlyAndStrictRoutes(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, path := installDeviceNotesFixture(t, o)
	r, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, login)
	}
	v := readDeviceNotesFixture(t, o, path)
	if v.CanWrite {
		t.Fatal("named writer")
	}
	if r, _ := o.call(t, "POST", path, deviceNotesBody(v, "1"), login["csrfToken"].(string), nil); r.StatusCode != 403 {
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

func TestDeviceNotesIdentityRenewalReplacementAndSessionBinding(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := readDeviceNotesFixture(t, o, path)
	body := deviceNotesBody(before, "1")
	if r, v := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	// Renewal retains original identity; neither a changed display name nor a
	// fresh leaf may migrate the notebook onto a replacement original identity.
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	f.devices[0].AgentCertificate.ExpiresAt = &f.inputs[0].AuthorityUntil
	f.devices[0].Name = "Renamed display"
	if v := readDeviceNotesFixture(t, o, path); v.Revision != 1 || v.IdentityKey != before.IdentityKey {
		t.Fatal("renewal lost notes")
	}
	f.inputs[0].CertificateHash = strings.Repeat("d", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	if v := readDeviceNotesFixture(t, o, path); v.Revision != 0 || len(v.Notes) != 0 || v.IdentityKey == before.IdentityKey {
		t.Fatal("replacement inherited notes")
	}
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("old identity token accepted", r.StatusCode)
	}
	newView := readDeviceNotesFixture(t, o, path)
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("logout", r.StatusCode)
	}
	_, login = o.login(t)
	csrf = login["csrfToken"].(string)
	if r, _ := o.call(t, "POST", path, deviceNotesBody(newView, "2"), csrf, nil); r.StatusCode != 409 {
		t.Fatal("old session token accepted", r.StatusCode)
	}
}

func TestDeviceNotesCommittedThenFinalGuardIsUnconfirmedAndReconciles(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceNotesFixture(t, o, path)
	body := deviceNotesBody(v, "5")
	f.onGuard = func(n int) {
		if n == 5 {
			f.inputs[0].Authorized = false
		}
	}
	r, result := o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 503 || result["error"].(map[string]any)["code"] != "device_notes_unconfirmed" {
		t.Fatal("committed write presented as rejected", r.StatusCode, result)
	}
	f.onGuard = nil
	f.inputs[0].Authorized = true
	saved := readDeviceNotesFixture(t, o, path)
	if saved.Revision != 1 || len(saved.Notes) != 1 || len(saved.Operations) != 1 || saved.Operations[0].ID != body["operationId"] {
		t.Fatal("lost durable reconciliation", saved)
	}
}

func TestDeviceNotesWorstCaseEscapedResponseFitsPrivateBound(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	o.login(t)
	manager, now, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if err != nil {
		t.Fatal(err)
	}
	id := f.inputs[0].DeviceID
	identity := devices[id].identity
	for i := 1; i <= 25; i++ {
		suffix := fmt.Sprintf("%032x", i)
		_, err = o.app.store.ApplyDeviceNote(context.Background(), manager, identity, id, "noteop_"+suffix, "add", "note_"+suffix, strings.Repeat("<", 2000), uint64(i-1), now, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	v := readDeviceNotesFixture(t, o, path)
	raw, _ := json.Marshal(v)
	if len(v.Notes) != 25 || len(raw) <= 128*1024 || len(raw) >= deviceNotesResponseBytes {
		t.Fatal("worst escaped budget", len(raw))
	}
}

func TestDeviceNotesReadRefusesRetainedFutureTimestamps(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceNotesFixture(t, o, path)
	if r, result := o.call(t, "POST", path, deviceNotesBody(v, "6"), csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, result)
	}
	f.now = f.now.Add(-time.Second)
	if r, result := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 503 {
		t.Fatal("future note exposed", r.StatusCode, result)
	}
}

func TestDeviceNotesNegativeReadFloorRejectsRollbackAcrossHandlers(t *testing.T) {
	for _, otherHandler := range []bool{false, true} {
		t.Run(fmt.Sprint(otherHandler), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			f, path := installDeviceNotesFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceNotesFixture(t, o, path)
			body := deviceNotesBody(v, "7")
			original := f.now
			f.now = v.ValidUntil
			negative := readDeviceNotesFixture(t, o, path)
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
			if r, result := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 || result["error"].(map[string]any)["code"] != "device_notes_rejected" {
				t.Fatal("rollback reopened original review", r.StatusCode, result)
			}
			f.now = v.ValidUntil
			if got := readDeviceNotesFixture(t, o, path); got.Revision != 0 {
				t.Fatal("late write committed")
			}
		})
	}
}

func TestDeviceNotesNewSigningKeyRejectsOldReviewWithResetClockFloor(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceNotesFixture(t, o, path)
	body := deviceNotesBody(v, "8")
	h := o.server.Config.Handler.(*operatorHandler)
	fresh, err := New(o.app.store, o.app.port, o.app.web, o.app.sampleDevice())
	if err != nil || fresh.csrf == o.app.csrf {
		t.Fatal("new process signing key", err)
	}
	h.app = fresh // retain old auth only to isolate key-epoch rejection in this test
	if r, result := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 || result["error"].(map[string]any)["code"] != "device_notes_rejected" {
		t.Fatal("old key review accepted", r.StatusCode, result)
	}
	if current := readDeviceNotesFixture(t, o, path); current.Revision != 0 || current.IdentityKey != v.IdentityKey {
		t.Fatal("restart changed original journal identity")
	}
	_ = f
}

// A controllable, serialized source lease mirrors the production enrollment
// BEGIN IMMEDIATE ordering without touching enrollment or executing an endpoint.
type serializedDeviceNotesSource struct {
	*fixtureMonitoringSource
	leaseMu     sync.Mutex
	clock       atomic.Int64
	guardHook   func(int)
	beforeLease func(int64)
	leaseCalls  atomic.Int64
}

func (f *serializedDeviceNotesSource) Now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
func (f *serializedDeviceNotesSource) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, fn func(func(time.Time) error) error) error {
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
func installSerializedDeviceNotes(t *testing.T, o operatorFixture) (*serializedDeviceNotesSource, string) {
	t.Helper()
	f, path := installDeviceNotesFixture(t, o)
	s := &serializedDeviceNotesSource{fixtureMonitoringSource: f}
	s.clock.Store(f.now.UnixNano())
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{s}
	return s, path
}

func TestDeviceNotesNegativeReadWaitsForAdmittedWriter(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%v", commit), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			s, path := installSerializedDeviceNotes(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceNotesFixture(t, o, path)
			body := deviceNotesBody(v, "9")
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

func TestDeviceNotesDelayedWriterLosesToTerminalRead(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	s, path := installSerializedDeviceNotes(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceNotesFixture(t, o, path)
	body := deviceNotesBody(v, "a")
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
	negative := readDeviceNotesFixture(t, o, path)
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
	if current := readDeviceNotesFixture(t, o, path); current.Revision != 0 {
		t.Fatal("late commit after terminal read")
	}
}

func TestDeviceNotesSameTimeConcurrentReads(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, path := installSerializedDeviceNotes(t, o)
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

func TestDeviceNotesExpiryAndFinalAuthorityFailureAreClosed(t *testing.T) {
	for _, kind := range []string{"expiry", "revoke", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			f, path := installDeviceNotesFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			v := readDeviceNotesFixture(t, o, path)
			body := deviceNotesBody(v, "1")
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
			stored, err := o.app.store.ReadDeviceNotes(context.Background(), manager, identity, f.inputs[0].DeviceID)
			if err != nil || stored.Revision != 0 {
				t.Fatal("failed final guard changed notes", stored, err)
			}
		})
	}
}

func TestDeviceNotesInputAndPlatformBounds(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f, path := installDeviceNotesFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readDeviceNotesFixture(t, o, path)
	for _, text := range []string{"", " padded ", strings.Repeat("é", 1001), "secret\u202econtrol", "line\x00control"} {
		body := deviceNotesBody(v, "1")
		body["text"] = text
		if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
			t.Fatal("invalid text", r.StatusCode)
		}
	}
	body := deviceNotesBody(v, "1")
	body["extra"] = true
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("unknown field", r.StatusCode)
	}
	f.snapshots[0].Platform = "linux"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 404 {
		t.Fatal("unsupported platform", r.StatusCode)
	}
}
