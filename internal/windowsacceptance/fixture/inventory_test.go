package fixture

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowsmanaged"
)

func inventorySelection(httpTest bool) profile.Selection {
	s := profile.InventoryTLS()
	if httpTest {
		s.Transport = "http-test"
	}
	return s
}

// Every value is invented. This constructs a transport object directly and
// never calls a native collector, starts a listener, or accesses endpoint state.
func inventoryFrame(at time.Time, seq uint64, generation string) lanstore.Frame {
	f := inventedFrame("windows", seq, at)
	f.SchemaVersion = lanstore.FrameWindowsInventoryVersion
	v := 12.5
	d := &f.Observation.Observation
	d.CPU.Quality, d.CPU.Value = "healthy", &v
	d.Memory.Quality, d.Memory.Value = "healthy", &v
	d.Disk.Quality, d.Disk.Value = "healthy", &v
	f.WindowsInventory = &windowsmanaged.Snapshot{
		SchemaVersion: windowsmanaged.SchemaVersion, CollectionProfile: windowsmanaged.CollectionProfile,
		GenerationID: generation, CollectedAt: at,
		Hostname:  windowsmanaged.Section[windowsmanaged.Hostname]{Source: "Invented fixture", Scope: "Synthetic hostname", Quality: "healthy", ObservedCount: 1, CountExact: true, Complete: true, Rows: []windowsmanaged.Hostname{{Value: "INVENTED-HOST"}}},
		Processes: emptySection[windowsmanaged.Process](), Services: emptySection[windowsmanaged.Service](), Software: emptySection[windowsmanaged.Software](), Network: emptySection[windowsmanaged.InterfaceAddress](),
	}
	return f
}

func emptySection[T any]() windowsmanaged.Section[T] {
	return windowsmanaged.Section[T]{Source: "Invented fixture", Scope: "Synthetic empty observation", Quality: "healthy", CountExact: true, Complete: true, Rows: []T{}}
}

func activateSynthetic(c *syntheticClient) { c.claim(); c.approve(); c.activate() }
func serveAgent(c *syntheticClient, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c.f.serve(w, r, true)
	return w
}

func TestSelectedBootstrapLifecycleAndInventory(t *testing.T) {
	for _, selection := range []profile.Selection{profile.BasicTLS(), profile.InventoryTLS(), inventorySelection(true)} {
		t.Run(selection.CollectionProfile+"/"+selection.Transport, func(t *testing.T) {
			c := syntheticSelected(t, selection)
			b := c.f.Bootstrap()
			if b.Profile != selection.Transport || b.CollectionProfile != selection.CollectionProfile || (b.ServerCAPEM == "") != selection.HTTPTest() || c.f.Snapshot().Binding.Profile != selection.Transport || c.f.Snapshot().Binding.CollectionProfile != selection.CollectionProfile {
				t.Fatal("bootstrap or authority is not selection-bound")
			}
			if c.f.Evidence().Inventory != profile.ZeroObservation() {
				t.Fatal("unobserved inventory acquired qualities")
			}
			cc := c.challenge("claim")
			if cc.Profile != selection.Transport || cc.CollectionProfile != selection.CollectionProfile {
				t.Fatal("challenge lost selection")
			}
			activateSynthetic(c)
			if c.cert.Intent().Profile != selection.Transport || c.cert.Intent().CollectionProfile != selection.CollectionProfile {
				t.Fatal("issued credential lost selection")
			}
			f := inventedFrame("windows", 1, *c.now)
			if selection.Inventory() {
				f = inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			}
			receipt(t, c.post(selection.TelemetryPath(), encoded(t, f), true))
			e := c.f.Evidence()
			if e.Transport != selection.Transport || e.CollectionProfile != selection.CollectionProfile || e.Frames != 1 || e.Inventory.Validate() != nil || e.Inventory.Usable() != selection.Inventory() {
				t.Fatal("selected receipt evidence is invalid")
			}
			if !selection.Inventory() && e.Inventory != profile.ZeroObservation() {
				t.Fatal("basic frame acquired inventory evidence")
			}
			raw := encoded(t, e)
			for _, forbidden := range []string{"INVENTED-HOST", "generationId", "sample_", "collectedAt", "rows", "12.5"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Fatal("evidence retained telemetry content")
				}
			}
		})
	}
}

func TestSelectedFixtureRejectsInvalidSelectionAndOrigins(t *testing.T) {
	for _, s := range []profile.Selection{{}, {CollectionProfile: "basic-readonly-v1", Transport: "http-test"}, {CollectionProfile: "managed-operations-v3", Transport: "tls"}} {
		if f, e := newFixtureSelected(context.Background(), "https://127.0.0.1:18443", "https://127.0.0.1:18444", time.Now, s); e == nil || f != nil {
			t.Fatal("unsupported selection admitted")
		}
	}
	for _, origin := range []string{"https://192.0.2.1:18443", "http://127.0.0.1:18443", "https://localhost:18443", "https://127.0.0.1:18443/", "https://127.0.0.1:18443?", "https://127.0.0.1:018443"} {
		if f, e := newFixtureSelected(context.Background(), origin, "https://127.0.0.1:18444", time.Now, profile.InventoryTLS()); e == nil || f != nil {
			t.Fatal("unbounded or mismatched origin admitted")
		}
	}
}

func TestSelectedProofAndRouteConfusion(t *testing.T) {
	for _, selection := range []profile.Selection{profile.InventoryTLS(), inventorySelection(true)} {
		t.Run(selection.Transport, func(t *testing.T) {
			c := syntheticSelected(t, selection)
			challenge := encoded(t, map[string]string{"invitationId": c.f.Bootstrap().InvitationID, "claimId": c.claimID, "purpose": "claim"})
			if w := c.post(prefix+"challenge", challenge, false); w.Code != 400 {
				t.Fatal("basic enrollment route reached inventory domain")
			}
			cc := c.challenge("claim")
			cc.CollectionProfile = enrollmentcrypto.CollectionProfile
			raw := c.claimBytes(cc)
			defer clear(raw)
			if w := c.post(selection.EnrollmentPrefix()+"claim", raw, false); w.Code != 401 {
				t.Fatal("valid basic proof crossed inventory challenge")
			}
			activateSynthetic(c)
			basic := encoded(t, inventedFrame("windows", 1, *c.now))
			if w := c.post(selection.TelemetryPath(), basic, true); w.Code != 400 {
				t.Fatal("basic body accepted by inventory domain")
			}
			r := c.request(selection.TelemetryPath(), encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))), true)
			r.URL.Path = telemetryPath
			if w := serveAgent(c, r); w.Code != 400 {
				t.Fatal("inventory body crossed basic route")
			}
			if c.f.Evidence().Frames != 0 {
				t.Fatal("profile confusion changed replay state")
			}
		})
	}
	c := synthetic(t)
	activateSynthetic(c)
	if w := c.post(telemetryPath, encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))), true); w.Code != 400 {
		t.Fatal("inventory body crossed basic profile")
	}
}

func TestInventoryHTTPProofsAndOriginalReceipt(t *testing.T) {
	c := syntheticSelected(t, inventorySelection(true))
	activateSynthetic(c)
	p := c.f.state.selection.TelemetryPath()
	firstRaw := encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	defer clear(firstRaw)
	for _, kind := range []string{"missing", "wrong", "changed-body", "wrong-path-signature", "wrong-sequence", "wrong-time", "tls-fallback", "extra-header", "duplicate-signature"} {
		t.Run(kind, func(t *testing.T) {
			r := c.request(p, firstRaw, true)
			switch kind {
			case "missing":
				r.Header.Del(signedhttp.SignatureHeader)
			case "wrong":
				r.Header.Set(signedhttp.SignatureHeader, base64.RawStdEncoding.EncodeToString(make([]byte, 64)))
			case "changed-body":
				raw := bytes.Replace(firstRaw, []byte("INVENTED-HOST"), []byte("ALTERED-HOST!"), 1)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				r.ContentLength = int64(len(raw))
			case "wrong-path-signature", "wrong-sequence", "wrong-time":
				path, seq, at := p, uint64(1), *c.now
				if kind == "wrong-path-signature" {
					path = signedhttp.Path
				}
				if kind == "wrong-sequence" {
					seq = 2
				}
				if kind == "wrong-time" {
					at = at.Add(-time.Second)
				}
				var err error
				r, err = signedhttp.NewSignedRequestForPath(context.Background(), c.f.Bootstrap().AgentOrigin, path, tls.Certificate{Certificate: [][]byte{c.cert.DER()}, PrivateKey: c.key}, seq, at, firstRaw)
				if err != nil {
					t.Fatal("synthetic signing failed")
				}
				r.RemoteAddr = "127.0.0.1:20000"
				r.URL.Path = p
			case "tls-fallback":
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			case "extra-header":
				r.Header.Set("X-Tracebolt-Unknown", "invented")
			case "duplicate-signature":
				r.Header.Add(signedhttp.SignatureHeader, r.Header.Get(signedhttp.SignatureHeader))
			}
			if w := serveAgent(c, r); w.Code < 400 || c.f.Evidence().Frames != 0 {
				t.Fatal("invalid signed request committed telemetry")
			}
		})
	}
	first := receipt(t, c.post(p, firstRaw, true))
	*c.now = c.now.Add(time.Second)
	dup := receipt(t, c.post(p, firstRaw, true))
	if !dup.Duplicate || !dup.ReceivedAt.Equal(first.ReceivedAt) || !dup.CollectedAt.Equal(first.CollectedAt) || c.f.Evidence().Inventory.Frames != 1 {
		t.Fatal("duplicate refreshed original receipt or inventory")
	}
	receipt(t, c.post(p, encoded(t, inventoryFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32))), true))
	if w := c.post(p, firstRaw, true); w.Code != 409 {
		t.Fatal("older signed frame replay accepted after progress")
	}
}

func TestInventoryTLSRejectsSignedFallback(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	activateSynthetic(c)
	raw := encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	for _, peer := range []bool{false, true} {
		r := c.request(c.f.state.selection.TelemetryPath(), raw, peer)
		r.Header.Set(signedhttp.CertificateHeader, base64.RawStdEncoding.EncodeToString(c.cert.DER()))
		r.Header.Set(signedhttp.SignatureHeader, "invented")
		if w := serveAgent(c, r); w.Code != 400 {
			t.Fatal("TLS admitted signed HTTP fallback")
		}
	}
}

func TestInventoryGenerationAndCaptureFences(t *testing.T) {
	for _, selection := range []profile.Selection{profile.InventoryTLS(), inventorySelection(true)} {
		t.Run(selection.Transport, func(t *testing.T) {
			c := syntheticSelected(t, selection)
			activateSynthetic(c)
			p := selection.TelemetryPath()
			at := *c.now
			first := inventoryFrame(at, 1, "sample_"+strings.Repeat("1", 32))
			first.Observation.GeneratedAt = at.Add(2 * time.Second)
			*c.now = at.Add(3 * time.Second)
			receipt(t, c.post(p, encoded(t, first), true))
			*c.now = c.now.Add(time.Second)
			for _, kind := range []string{"generation", "inventory-time", "collected", "generated"} {
				f := inventoryFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32))
				switch kind {
				case "generation":
					f.WindowsInventory.GenerationID = first.WindowsInventory.GenerationID
				case "inventory-time":
					f.WindowsInventory.CollectedAt = at
				case "collected":
					f.WindowsInventory.CollectedAt = at
					f.Observation.Observation.LastSeen = at
					f.Observation.Observation.CPU.CollectedAt = at
					f.Observation.Observation.Memory.CollectedAt = at
					f.Observation.Observation.Disk.CollectedAt = at
				case "generated":
					f = inventoryFrame(at.Add(time.Second), 2, "sample_"+strings.Repeat("2", 32))
					f.Observation.GeneratedAt = first.Observation.GeneratedAt
				}
				raw := encoded(t, f)
				if _, e := lanstore.ValidateFrame(raw, *c.now); e != nil {
					t.Fatal("replay candidate is not schema valid", kind)
				}
				if w := c.post(p, raw, true); w.Code != 409 || c.f.Evidence().Inventory.Frames != 1 {
					t.Fatal("nonadvancing frame admitted", kind)
				}
			}
			receipt(t, c.post(p, encoded(t, inventoryFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32))), true))
		})
	}
}

func TestInventoryQualityEvidenceRemainsHonest(t *testing.T) {
	c := syntheticSelected(t, profile.InventoryTLS())
	activateSynthetic(c)
	f := inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
	f.Observation.Observation.CPU.Quality, f.Observation.Observation.CPU.Value = "unknown", nil
	f.Observation.Observation.Memory.Quality, f.Observation.Observation.Memory.Value = "denied", nil
	s := f.WindowsInventory
	s.Services.Quality, s.Services.Complete, s.Services.CountExact = "denied", false, false
	s.Software.Quality, s.Software.Complete, s.Software.CountExact = "unavailable", false, false
	s.Processes.Quality, s.Processes.Complete, s.Processes.CountExact = "partial", false, false
	receipt(t, c.post(c.f.state.selection.TelemetryPath(), encoded(t, f), true))
	e := c.f.Evidence().Inventory
	if e.Validate() != nil || e.Usable() || e.Frames != 1 || e.CPU != "unavailable" || e.Memory != "denied" || e.Processes != "partial" || e.Services != "denied" || e.Software != "unavailable" {
		t.Fatal("denied or unavailable data became successful inventory")
	}
	var keys map[string]any
	if json.Unmarshal(encoded(t, e), &keys) != nil || len(keys) != 9 {
		t.Fatal("inventory evidence widened")
	}
}

type transitionBody struct {
	io.ReadCloser
	transition func()
}

func (b *transitionBody) Read(p []byte) (int, error) {
	if b.transition != nil {
		transition := b.transition
		b.transition = nil
		transition()
	}
	return b.ReadCloser.Read(p)
}

func TestInventoryHTTPCurrentAuthorityRechecked(t *testing.T) {
	c := syntheticSelected(t, inventorySelection(true))
	c.claim()
	c.approve()
	p := c.f.state.selection.TelemetryPath()
	raw := encoded(t, inventoryFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32)))
	if w := c.post(p, raw, true); w.Code != 403 {
		t.Fatal("issued but inactive certificate accepted")
	}
	c.activate()
	other := syntheticSelected(t, inventorySelection(true))
	activateSynthetic(other)
	r, err := signedhttp.NewSignedRequestForPath(context.Background(), c.f.Bootstrap().AgentOrigin, p, tls.Certificate{Certificate: [][]byte{other.cert.DER()}, PrivateKey: other.key}, 1, *c.now, raw)
	if err != nil {
		t.Fatal("synthetic unrelated signing failed")
	}
	r.RemoteAddr = "127.0.0.1:20000"
	if w := serveAgent(c, r); w.Code != 403 {
		t.Fatal("another fixture's activated identity was accepted")
	}
	r = c.request(p, raw, true)
	r.Body = &transitionBody{ReadCloser: r.Body, transition: func() { c.f.ToggleUnavailable(true) }}
	if w := serveAgent(c, r); w.Code != 403 || c.f.Evidence().Frames != 0 {
		t.Fatal("slow request retained authority after outage")
	}
	c.f.ToggleUnavailable(false)
	// Exercise the final locked check after Verify has returned successfully.
	r = c.request(p, raw, true)
	verified, err := c.f.state.signed.Verify(r)
	if err != nil {
		t.Fatal("synthetic verifier rejected valid request")
	}
	defer clear(verified.Body)
	*c.now = time.Unix(c.f.Snapshot().Intent.NotAfter, 0).UTC()
	w := httptest.NewRecorder()
	c.f.state.mu.Lock()
	c.f.state.telemetry(w, r, verified.Body, &verified)
	c.f.state.mu.Unlock()
	if w.Code != 403 || c.f.Evidence().Frames != 0 {
		t.Fatal("expired authority committed after verification")
	}
}
