package fixture

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanstore"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsacceptance/profile"
)

func checkedTelemetry(t *testing.T, c *syntheticClient) TelemetryObservation {
	t.Helper()
	e := c.f.Evidence()
	if e.Telemetry.Validate() != nil || e.Telemetry.Accepted != e.Frames || e.Telemetry.Duplicate != e.DuplicateReceipts {
		t.Fatal("inconsistent finite receiver counters")
	}
	return e.Telemetry
}

func TestTelemetryProgressSeparatesDeniedCollectionFromReceiverRejection(t *testing.T) {
	for _, selection := range []profile.Selection{profile.InventoryTLS(), inventorySelection(true)} {
		t.Run(selection.Transport, func(t *testing.T) {
			c := syntheticSelected(t, selection)
			activateSynthetic(c)
			if checkedTelemetry(t, c) != (TelemetryObservation{}) {
				t.Fatal("enrollment counted as telemetry")
			}
			f := inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			f.WindowsInventory.Services.Quality = "denied"
			f.WindowsInventory.Services.Complete = false
			f.WindowsInventory.Services.CountExact = false
			raw := encoded(t, f)
			receipt(t, c.post(selection.TelemetryPath(), raw, true))
			if got := checkedTelemetry(t, c); got != (TelemetryObservation{Admitted: 1, Accepted: 1}) || c.f.Evidence().Inventory.Usable() {
				t.Fatal("accepted native denial became receiver rejection or usable inventory")
			}
			*c.now = c.now.Add(time.Second)
			if !receipt(t, c.post(selection.TelemetryPath(), raw, true)).Duplicate {
				t.Fatal("exact retry not duplicate")
			}
			if got := checkedTelemetry(t, c); got != (TelemetryObservation{Admitted: 2, Accepted: 1, Duplicate: 1}) {
				t.Fatal("duplicate became another accepted frame")
			}
		})
	}
}

func TestTelemetryProgressFiniteRejectionCheckpoints(t *testing.T) {
	for _, which := range []string{"authorization", "body", "frame", "scope", "freshness", "outage-before-body", "outage-during-body"} {
		t.Run(which, func(t *testing.T) {
			c := syntheticSelected(t, profile.InventoryTLS())
			activateSynthetic(c)
			path := c.f.state.selection.TelemetryPath()
			f := inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			want := TelemetryObservation{Admitted: 1}
			peer, code := true, 400
			switch which {
			case "authorization":
				peer, code = false, 403
				want.AuthorizationRejected = 1
			case "body":
				want.BodyRejected = 1
			case "frame":
				want.FrameRejected = 1
			case "scope":
				f = expandedFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
				want.ScopeRejected = 1
			case "freshness":
				receipt(t, c.post(path, encoded(t, f), true))
				f.Sequence = 2 // Different body but the same original captures.
				want.Admitted, want.Accepted, want.FreshnessRejected, code = 2, 1, 1, 409
			case "outage-before-body", "outage-during-body":
				want.Unavailable, code = 1, 503
			}
			raw := encoded(t, f)
			if which == "frame" {
				raw = []byte(`{"PRIVATE_PATH":"PRIVATE_TELEMETRY"}`)
			}
			r := c.request(path, raw, peer)
			if which == "body" {
				r.Body = io.NopCloser(bytes.NewReader(raw[:len(raw)-1]))
			}
			if which == "outage-before-body" {
				c.f.ToggleUnavailable(true)
			}
			if which == "outage-during-body" {
				r.Body = &transitionBody{ReadCloser: r.Body, transition: func() { c.f.ToggleUnavailable(true) }}
			}
			if w := serveAgent(c, r); w.Code != code {
				t.Fatal("protocol result changed", w.Code)
			}
			if got := checkedTelemetry(t, c); got != want {
				t.Fatal("wrong finite rejection checkpoint", got, want)
			}
		})
	}
}

func TestTelemetryProgressSignedRequestRejection(t *testing.T) {
	c := syntheticSelected(t, inventorySelection(true))
	activateSynthetic(c)
	raw := encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	r := c.request(c.f.state.selection.TelemetryPath(), raw, true)
	r.Header.Set(signedhttp.SignatureHeader, "not-a-valid-signature")
	if w := serveAgent(c, r); w.Code != 403 {
		t.Fatal("invalid signature admitted")
	}
	if got := checkedTelemetry(t, c); got != (TelemetryObservation{Admitted: 1, AuthorizationRejected: 1}) {
		t.Fatal("verification rejection uncounted")
	}
}

func TestTelemetryProgressExcludesPreAdmissionFailures(t *testing.T) {
	for _, which := range []string{"envelope", "size", "capacity", "closed", "slots"} {
		t.Run(which, func(t *testing.T) {
			c := syntheticSelected(t, profile.InventoryTLS())
			activateSynthetic(c)
			r := c.request(c.f.state.selection.TelemetryPath(), encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))), true)
			switch which {
			case "envelope":
				r.URL.RawQuery = "PRIVATE"
			case "size":
				r.ContentLength = lanstore.MaxFrameBytes + 1
			case "capacity":
				c.f.state.requests = MaxRequests
			case "closed":
				_ = c.f.Close()
			case "slots":
				c.f.state.slots <- struct{}{}
				c.f.state.slots <- struct{}{}
			}
			if w := serveAgent(c, r); w.Code == 200 {
				t.Fatal("pre-admission failure accepted")
			}
			if checkedTelemetry(t, c) != (TelemetryObservation{}) {
				t.Fatal("unadmitted request counted")
			}
		})
	}
}

func TestTelemetryProgressAdmissionBoundAndReceiptCapacity(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	activateSynthetic(c)
	path := c.f.state.selection.TelemetryPath()
	for i := uint64(1); i <= MaxFrames; i++ {
		raw := encoded(t, inventoryFrame(*c.now, i, "sample_"+strings.Repeat("1", 31)+string("0123456789abcdef"[i%16])))
		receipt(t, c.post(path, raw, true))
		*c.now = c.now.Add(time.Second)
	}
	if w := c.post(path, encoded(t, inventoryFrame(*c.now, MaxFrames+1, "sample_"+strings.Repeat("2", 32))), true); w.Code != 503 {
		t.Fatal("frame cap changed")
	}
	if got := checkedTelemetry(t, c); got != (TelemetryObservation{Admitted: MaxFrames + 1, Accepted: MaxFrames, Unavailable: 1}) {
		t.Fatal("receipt capacity outcome missing")
	}
	c.f.ToggleUnavailable(true)
	for c.f.Evidence().Requests < MaxRequests {
		if w := c.post(path, []byte(`{}`), false); w.Code != 503 {
			t.Fatal("outage admitted body")
		}
	}
	before := checkedTelemetry(t, c)
	if before.Admitted > MaxRequests {
		t.Fatal("admission counter overflow")
	}
	_ = c.post(path, []byte(`{}`), false)
	if checkedTelemetry(t, c) != before {
		t.Fatal("request bound changed after exhaustion")
	}
}

func TestTelemetryProgressAtomicInFlightObservation(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	activateSynthetic(c)
	raw := encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	r := c.request(c.f.state.selection.TelemetryPath(), raw, true)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.Body = &transitionBody{ReadCloser: r.Body, transition: func() { close(entered); <-release }}
	w := httptest.NewRecorder()
	go func() { defer close(done); c.f.serve(w, r, true) }()
	<-entered
	for i := 0; i < 50; i++ {
		if got := checkedTelemetry(t, c); got != (TelemetryObservation{Admitted: 1, InFlight: 1}) {
			t.Fatal("in-flight progress inconsistent")
		}
	}
	close(release)
	<-done
	if w.Code != 200 || checkedTelemetry(t, c) != (TelemetryObservation{Admitted: 1, Accepted: 1}) {
		t.Fatal("accepted progress inconsistent")
	}
}

func TestTelemetryObservationValidationAndPrivateFieldExclusion(t *testing.T) {
	valid := []TelemetryObservation{{}, {Admitted: 2, InFlight: 2}, {Admitted: MaxRequests, Unavailable: MaxRequests}, {Admitted: 3, Accepted: 1, Duplicate: 2}}
	for _, o := range valid {
		if o.Validate() != nil {
			t.Fatal("valid finite counters rejected")
		}
	}
	invalid := []TelemetryObservation{{Admitted: 1}, {Accepted: 1}, {Admitted: 1, Duplicate: 1}, {Admitted: 3, InFlight: 3}, {Admitted: 65, Accepted: 65}, {Admitted: MaxRequests + 1, Unavailable: MaxRequests + 1}, {Admitted: 1, AuthorizationRejected: ^uint64(0)}}
	for _, o := range invalid {
		if o.Validate() == nil {
			t.Fatal("malformed counters accepted")
		}
	}
	raw, err := json.Marshal(TelemetryObservation{Admitted: 1, FrameRejected: 1})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]uint64
	if json.Unmarshal(raw, &keys) != nil || len(keys) != 10 {
		t.Fatal("unexpected diagnostic shape")
	}
	for _, key := range []string{"admitted", "inFlight", "accepted", "duplicate", "authorizationRejected", "bodyRejected", "frameRejected", "scopeRejected", "freshnessRejected", "unavailable"} {
		if _, ok := keys[key]; !ok {
			t.Fatal("missing fixed key")
		}
	}
}
