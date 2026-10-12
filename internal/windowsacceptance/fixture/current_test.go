package fixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowssetup"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
)

// Synthetic handler tests only: no listeners, protected files, native provider
// calls, service installation or privilege changes.
func syntheticCurrent(t *testing.T) *syntheticClient {
	c := syntheticSelected(t, profile.InventoryTLS())
	_ = c.f.Close()
	f, e := newFixtureMode(context.Background(), "https://127.0.0.1:18443", "https://127.0.0.1:18444", func() time.Time { return *c.now }, profile.InventoryTLS(), true)
	if e != nil {
		t.Fatal(e)
	}
	c.f = f
	t.Cleanup(func() { _ = f.Close() })
	return c
}
func activateCurrent(c *syntheticClient) {
	cc := c.challenge("claim")
	secret, e := c.f.Secret(context.Background())
	if e != nil {
		c.t.Fatal(e)
	}
	defer clear(secret)
	msg, e := enrollmentcrypto.ClaimSigningMessage(cc, c.claimRequest, c.csr, string(secret), *c.now)
	if e != nil {
		c.t.Fatal(e)
	}
	defer clear(msg)
	fields := base(cc)
	fields["schemaVersion"] = enrollmentcrypto.RenewableClaimVersion
	fields["renewalPolicy"] = cc.RenewalPolicy
	fields["agentOrigin"] = cc.AgentOrigin
	fields["requestId"] = c.claimRequest
	fields["invitationSecret"] = string(secret)
	fields["csr"] = base64.RawStdEncoding.EncodeToString(c.csr)
	fields["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(c.key, msg))
	raw := encoded(c.t, fields)
	defer clear(raw)
	if w := c.post(c.f.state.selection.EnrollmentPrefix()+"claim", raw, false); w.Code != 200 {
		c.t.Fatal("current claim rejected", w.Code)
	}
	c.approve()
	c.activate()
}
func currentFrame(at time.Time, seq uint64, generation string) lanstore.Frame {
	f := expandedFrame(at, seq, generation)
	f.SchemaVersion = lanstore.FrameWindowsStorageIOVersion
	g := gToken()
	startup, _ := windowsmanaged.CollectServiceStartupWithReaderAndClock(context.Background(), f.WindowsInventory.Services.Rows, generation, g, at, func(context.Context, string) (windowsmanaged.ServiceStartupRow, error) {
		panic("empty synthetic service rows must never invoke reader")
	}, func() time.Time { return at })
	f.WindowsServiceStartup = &startup
	f.WindowsAdapterContext = &windowsadapters.Snapshot{SchemaVersion: windowsadapters.SchemaVersion, Scope: windowsadapters.Scope, GrantID: g, GenerationID: generation, CollectedAt: at, Quality: "denied", Rows: []windowsadapters.Adapter{}}
	patch := windowspatchcontext.Empty(windowspatchcontext.Request{Consent: windowspatchcontext.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowspatchcontext.ErrUnavailable.Error())
	f.WindowsPatchContext = &patch
	security := windowssecurity.Empty(windowssecurity.Request{Consent: windowssecurity.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowssecurity.ErrDenied.Error())
	f.WindowsSecurityPosture = &security
	sessions := windowssessions.Empty(windowssessions.Request{Consent: windowssessions.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowssessions.ErrDenied.Error())
	f.WindowsSessionContext = &sessions
	hardware := windowshardware.Empty(windowshardware.Request{Consent: windowshardware.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowshardware.ErrDenied.Error())
	f.WindowsHardwareContext = &hardware
	storage := windowsstorage.Empty(windowsstorage.Request{Consent: windowsstorage.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowsstorage.ErrDenied.Error())
	f.WindowsStorageContext = &storage
	coverage := windowssecuritycoverage.Empty(windowssecuritycoverage.Request{Consent: windowssecuritycoverage.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowssecuritycoverage.ErrDenied.Error())
	f.WindowsSecurityCoverage = &coverage
	resources := windowsresourcecontext.Empty(windowsresourcecontext.Request{Consent: windowsresourcecontext.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowsresourcecontext.ErrDenied.Error())
	f.WindowsResourceContext = &resources
	io := windowsstorageio.Empty(windowsstorageio.Request{Consent: windowsstorageio.Consent{GrantID: g}, GenerationID: generation, CollectedAt: at}, windowsstorageio.ErrDenied.Error())
	f.WindowsStorageIO = &io
	// Production scopes have distinct local grant identifiers. Historical v5
	// test data intentionally reuses IDs; that is invalid for newer siblings.
	for i, grant := range []*string{&f.WindowsEvents.GrantID, &f.WindowsVolumes.GrantID, &f.WindowsProcessMetrics.GrantID, &f.WindowsNetwork.GrantID, &f.WindowsServiceStartup.GrantID, &f.WindowsAdapterContext.GrantID, &f.WindowsPatchContext.GrantID, &f.WindowsSecurityPosture.GrantID, &f.WindowsSessionContext.GrantID, &f.WindowsHardwareContext.GrantID, &f.WindowsStorageContext.GrantID, &f.WindowsSecurityCoverage.GrantID, &f.WindowsResourceContext.GrantID, &f.WindowsStorageIO.GrantID} {
		*grant = strings.Repeat(string("123456789abcde"[i]), 32)
	}
	return f
}
func postGeneration(c *syntheticClient, path string, raw []byte) *httptest.ResponseRecorder {
	r := c.request(c.f.state.selection.TelemetryPath(), raw, true)
	u := *r.URL
	u.Path = path
	r.URL = &u
	r.RequestURI = ""
	return serveAgent(c, r)
}
func generationRequests(c *syntheticClient, domain int, failure bool) ([][]byte, error) {
	device := c.cert.Intent().DeviceID
	binding := windowsfullprocesses.SenderBinding("tls", c.f.Bootstrap().AgentOrigin, c.cert.CertificateHash(), device)
	grant := strings.Repeat("b", 32)
	at := *c.now
	var out [][]byte
	switch domain {
	case 0:
		consent := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at}
		m := windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: device, Consent: consent}
		out = append(out, encoded(c.t, m))
		if failure {
			m.Operation = "failure"
			m.Sequence = 1
			m.AttemptedAt = &at
			m.Reason = "access_denied"
			out = append(out, encoded(c.t, m))
		} else {
			ms, e := windowsfullservices.Build(device, consent, 1, windowsfullservices.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullservices.Row{}})
			if e != nil {
				return nil, e
			}
			for _, m := range ms {
				out = append(out, encoded(c.t, m))
			}
		}
	case 1:
		consent := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at, HistoryScope: "windows-machine-software-history-v1"}
		m := windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: device, Consent: consent}
		out = append(out, encoded(c.t, m))
		if failure {
			m.Operation = "failure"
			m.Sequence = 1
			m.AttemptedAt = &at
			m.Reason = "unsupported"
			out = append(out, encoded(c.t, m))
		} else {
			ms, e := windowsfullsoftware.Build(device, consent, 1, windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullsoftware.Row{}})
			if e != nil {
				return nil, e
			}
			for _, m := range ms {
				out = append(out, encoded(c.t, m))
			}
		}
	case 2:
		consent := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at}
		m := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "scope", DeviceID: device, Consent: consent}
		out = append(out, encoded(c.t, m))
		if failure {
			m.Operation = "failure"
			m.Sequence = 1
			m.AttemptedAt = &at
			m.Reason = "resource_limit"
			out = append(out, encoded(c.t, m))
		} else {
			ms, e := windowsfullprocesses.Build(device, consent, 1, windowsfullprocesses.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullprocesses.Row{}})
			if e != nil {
				return nil, e
			}
			for _, m := range ms {
				out = append(out, encoded(c.t, m))
			}
		}
	case 3:
		consent := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at}
		m := windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: device, Consent: consent}
		out = append(out, encoded(c.t, m))
		if failure {
			m.Operation = "failure"
			m.Sequence = 1
			m.AttemptedAt = &at
			m.Reason = "deadline"
			out = append(out, encoded(c.t, m))
		} else {
			ms, e := windowsnetworkcontext.Build(device, consent, 1, windowsnetworkcontext.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsnetworkcontext.Row{}})
			if e != nil {
				return nil, e
			}
			for _, m := range ms {
				out = append(out, encoded(c.t, m))
			}
		}
	}
	return out, nil
}
func TestCurrentInitialRenewableEnrollmentAndCapabilities(t *testing.T) {
	c := syntheticCurrent(t)
	b := c.f.Bootstrap()
	if b.SchemaVersion != enrollmentclient.RenewableBootstrapVersion || b.RenewalPolicy != enrollmentcrypto.RenewalPolicySameKey || b.Profile != "tls" {
		t.Fatal("wrong current bootstrap")
	}
	if c.f.CurrentEvidence().Validate() != nil || c.f.CurrentEvidence().Ready() {
		t.Fatal("zero evidence")
	}
	for _, path := range []string{windowssetup.CapabilitiesPath, windowssetup.ReadAdminCapabilitiesPathV9, windowssetup.ReadAdminCapabilitiesPathV10} {
		r := c.request(c.f.state.selection.EnrollmentPrefix()+"challenge", []byte("{}"), false)
		r.Method = "GET"
		r.Body = nil
		r.ContentLength = 0
		r.Header.Del("Content-Type")
		r.URL.Path = path
		w := httptest.NewRecorder()
		c.f.serve(w, r, false)
		if path == windowssetup.ReadAdminCapabilitiesPathV10 {
			expected := windowssetup.ExpectedReadAdminV10(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
			if w.Code != 200 || windowssetup.Match(w.Body.Bytes(), expected) != nil {
				t.Fatal("current capabilities", w.Code)
			}
		} else if w.Code != 400 {
			t.Fatal("historical capability route promoted")
		}
	}
	activateCurrent(c)
	if c.cert.Intent().NotAfter-c.cert.Intent().NotBefore != 7*24*60*60 || c.f.CurrentEvidence().InitialCredentialGeneration != 1 {
		t.Fatal("initial renewable validity or generation")
	}
	if _, e := enrollmentcrypto.RenewalIdentityGeneration(c.cert.Intent()); e != nil {
		t.Fatal(e)
	}
}
func TestCurrentOrdinaryAndFourIndependentDomains(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "honest_failure"}[failure], func(t *testing.T) {
			c := syntheticCurrent(t)
			activateCurrent(c)
			frame := currentFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
			raw := encoded(t, frame)
			if _, e := lanstore.ValidateFrame(raw, *c.now); e != nil {
				t.Error("invalid invented current frame", e)
				for label, err := range map[string]error{
					"startup":  windowsmanaged.ValidateServiceStartup(*frame.WindowsServiceStartup),
					"adapter":  windowsadapters.Validate(*frame.WindowsAdapterContext),
					"patch":    windowspatchcontext.Validate(*frame.WindowsPatchContext),
					"security": windowssecurity.Validate(*frame.WindowsSecurityPosture),
					"sessions": windowssessions.Validate(*frame.WindowsSessionContext),
					"hardware": windowshardware.Validate(*frame.WindowsHardwareContext),
					"storage":  windowsstorage.Validate(*frame.WindowsStorageContext),
					"coverage": windowssecuritycoverage.Validate(*frame.WindowsSecurityCoverage),
					"resource": windowsresourcecontext.Validate(*frame.WindowsResourceContext),
					"io":       windowsstorageio.Validate(*frame.WindowsStorageIO),
				} {
					if err != nil {
						t.Errorf("%s: %v", label, err)
					}
				}
				t.FailNow()
			}
			receipt(t, c.post(c.f.state.selection.TelemetryPath(), raw, true))
			before := c.f.CurrentEvidence()
			if before.Ready() || before.Validate() != nil || before.AcceptedFrames != 1 || before.LastSequence != 1 || before.LastFrameSHA256 != digest(raw) {
				t.Fatal("ordinary progress invalid")
			}
			for i, d := range currentDomains {
				requests, e := generationRequests(c, i, failure)
				if e != nil {
					t.Fatal(e)
				}
				for _, body := range requests {
					var m currentMessage
					_ = json.Unmarshal(body, &m)
					w := postGeneration(c, d.path+m.Operation, body)
					if w.Code != 200 {
						t.Fatal(d.scope, m.Operation, w.Code)
					}
					var e error
					switch i {
					case 0:
						_, e = windowsfullservices.DecodeReceipt(w.Body.Bytes(), body)
					case 1:
						_, e = windowsfullsoftware.DecodeReceipt(w.Body.Bytes(), body)
					case 2:
						_, e = windowsfullprocesses.DecodeReceipt(w.Body.Bytes(), body)
					case 3:
						_, e = windowsnetworkcontext.DecodeReceipt(w.Body.Bytes(), body)
					}
					if e != nil {
						t.Fatal("non-production receipt", e)
					}
					snapshot := c.f.CurrentEvidence()
					dup := postGeneration(c, d.path+m.Operation, body)
					if dup.Code != 200 || !bytes.Equal(w.Body.Bytes(), dup.Body.Bytes()) || c.f.CurrentEvidence() != snapshot {
						t.Fatal("independent retry changed evidence")
					}
				}
			}
			out := c.f.CurrentEvidence()
			if out.Validate() != nil || !out.Ready() || out.AcceptedFrames != c.f.Evidence().Frames || out.LastSequence != c.f.Evidence().LastSequence {
				t.Fatal("current readiness or floors", out.Validate())
			}
			for _, source := range out.Sources {
				if source.Kind == "grant_only" && source.Samples != 0 {
					t.Fatal("grant promoted to history observations")
				}
			}
			encoded := encoded(t, out)
			for _, forbidden := range []string{"INVENTED-HOST", "Volume{", "127.0.0.1", "grantId", "senderBinding", "sample_", "privateKey", "captureStartedAt"} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatal("source data retained in public evidence", forbidden)
				}
			}
			if out.FullAcceptance || out.NativeProviderProof || out.RenewalCycleProved {
				t.Fatal("unproved claim")
			}
		})
	}
}
func TestCurrentSourceCaptureFloorsAndStrictTelemetry(t *testing.T) {
	c := syntheticCurrent(t)
	activateCurrent(c)
	f := currentFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))
	raw := encoded(t, f)
	receipt(t, c.post(c.f.state.selection.TelemetryPath(), raw, true))
	old := c.f.CurrentEvidence()
	*c.now = c.now.Add(time.Second)
	if !receipt(t, c.post(c.f.state.selection.TelemetryPath(), raw, true)).Duplicate || c.f.CurrentEvidence() != old {
		t.Fatal("ordinary retry")
	}
	newer := currentFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32))
	newer.WindowsStorageIO = f.WindowsStorageIO
	if w := c.post(c.f.state.selection.TelemetryPath(), encoded(t, newer), true); w.Code == 200 {
		t.Fatal("old storage capture advanced")
	}
	if c.f.CurrentEvidence() != old {
		t.Fatal("rejection changed metadata")
	}
	valid := encoded(t, currentFrame(*c.now, 2, "sample_"+strings.Repeat("2", 32)))
	bad := append(append([]byte{}, valid[:len(valid)-1]...), []byte(`,"unexpected":true}`)...)
	if w := c.post(c.f.state.selection.TelemetryPath(), bad, true); w.Code == 200 {
		t.Fatal("unknown field accepted")
	}
	receipt(t, c.post(c.f.state.selection.TelemetryPath(), valid, true))
	c.f.ToggleUnavailable(true)
	if w := c.post(c.f.state.selection.TelemetryPath(), valid, true); w.Code != 503 {
		t.Fatal("outage retry admitted")
	}
	c.f.ToggleUnavailable(false)
	if c.f.Evidence().Telemetry.Validate() != nil {
		t.Fatal("current counters inconsistent")
	}
}
func TestCurrentDoesNotBroadenLegacyOrTransport(t *testing.T) {
	if f, e := newFixtureMode(context.Background(), "http://127.0.0.1:18443", "http://127.0.0.1:18444", time.Now, inventorySelection(true), true); e == nil || f != nil {
		t.Fatal("current HTTP admitted")
	}
	c := syntheticSelected(t, profile.InventoryTLS())
	activateSynthetic(c)
	for _, d := range currentDomains {
		r := c.request(c.f.state.selection.TelemetryPath(), []byte("{}"), true)
		r.URL.Path = d.path + "scope"
		if w := serveAgent(c, r); w.Code != http.StatusBadRequest {
			t.Fatal("legacy independent route admitted")
		}
	}
	if w := c.post(c.f.state.selection.TelemetryPath(), encoded(t, currentFrame(*c.now, 1, "sample_"+strings.Repeat("1", 32))), true); w.Code != 400 {
		t.Fatal("legacy v16 promoted")
	}
}

func TestCurrentGenerationCrossChunkDigestFloorsAndAuthority(t *testing.T) {
	c := syntheticCurrent(t)
	activateCurrent(c)
	path := currentDomains[2].path
	requests, e := generationRequests(c, 2, false)
	if e != nil {
		t.Fatal(e)
	}
	var scope windowsfullprocesses.Message
	if json.Unmarshal(requests[0], &scope) != nil {
		t.Fatal("decode scope")
	}
	if w := postGeneration(c, path+"scope", requests[0]); w.Code != 200 {
		t.Fatal("scope", w.Code)
	}
	rows := make([]windowsfullprocesses.Row, 130)
	name := "private-row-name-not-evidence"
	for i := range rows {
		rows[i] = windowsfullprocesses.Row{PID: uint32(i), Name: &name, NameQuality: "observed", Threads: 1}
	}
	messages, e := windowsfullprocesses.Build(scope.DeviceID, scope.Consent, 1, windowsfullprocesses.Capture{StartedAt: *c.now, FinishedAt: *c.now, Complete: true, Rows: rows})
	if e != nil || len(messages) != 2 {
		t.Fatal("multi-chunk construction", e)
	}
	if w := postGeneration(c, path+"chunk", encoded(t, messages[1])); w.Code != 409 {
		t.Fatal("out of order chunk admitted", w.Code)
	}
	first := encoded(t, messages[0])
	if w := postGeneration(c, path+"chunk", first); w.Code != 200 {
		t.Fatal("first chunk", w.Code)
	}
	before := c.f.CurrentEvidence()
	broken := messages[1]
	broken.Rows = append([]windowsfullprocesses.Row{}, broken.Rows...)
	broken.Rows[0].PID = 1
	if w := postGeneration(c, path+"chunk", encoded(t, broken)); w.Code == 200 {
		t.Fatal("cross-chunk duplicate accepted")
	}
	if c.f.CurrentEvidence() != before {
		t.Fatal("failed chunk changed evidence")
	}
	broken = messages[1]
	broken.Rows = append([]windowsfullprocesses.Row{}, broken.Rows...)
	broken.Rows[0].Threads++
	if w := postGeneration(c, path+"chunk", encoded(t, broken)); w.Code == 200 {
		t.Fatal("whole-generation digest mismatch accepted")
	}
	final := encoded(t, messages[1])
	response := postGeneration(c, path+"chunk", final)
	if response.Code != 200 {
		t.Fatal("final chunk", response.Code)
	}
	if _, e := windowsfullprocesses.DecodeReceipt(response.Body.Bytes(), final); e != nil {
		t.Fatal(e)
	}
	out := c.f.CurrentEvidence()
	source := out.source(windowsfullprocesses.Scope)
	if source.Status != "complete" || source.Samples != 1 || source.Rows != 130 || source.Qualities.Observed != 130 {
		t.Fatal("whole generation projection", source)
	}
	if bytes.Contains(encoded(t, out), []byte(name)) {
		t.Fatal("row label escaped")
	}
	if g := c.f.state.currentGenerations[windowsfullprocesses.Scope]; g.lastOrder != "" || len(g.digestState) != 0 || len(g.seen) != 0 {
		t.Fatal("completed generation retained transient source state")
	}
	duplicate := postGeneration(c, path+"chunk", first)
	if duplicate.Code != 200 || c.f.CurrentEvidence() != out {
		t.Fatal("old exact chunk retry changed metadata")
	}
	// A higher sequence may not reuse an old original capture time.
	messages, e = windowsfullprocesses.Build(scope.DeviceID, scope.Consent, 2, windowsfullprocesses.Capture{StartedAt: *c.now, FinishedAt: *c.now, Complete: true, Rows: rows})
	if e != nil {
		t.Fatal(e)
	}
	if w := postGeneration(c, path+"chunk", encoded(t, messages[0])); w.Code != 409 {
		t.Fatal("capture floor bypass", w.Code)
	}
	*c.now = c.now.Add(time.Second)
	messages, e = windowsfullprocesses.Build(scope.DeviceID, scope.Consent, 2, windowsfullprocesses.Capture{StartedAt: *c.now, FinishedAt: *c.now, Complete: true, Rows: []windowsfullprocesses.Row{}})
	if e != nil {
		t.Fatal(e)
	}
	if w := postGeneration(c, path+"chunk", encoded(t, messages[0])); w.Code != 200 {
		t.Fatal("new generation", w.Code)
	}
	// Current TLS authority is checked even for an exact receipt retry.
	r := c.request(c.f.state.selection.TelemetryPath(), encoded(t, messages[0]), true)
	r.URL.Path = path + "chunk"
	r.TLS.PeerCertificates = nil
	if w := serveAgent(c, r); w.Code != 403 {
		t.Fatal("unauthorized duplicate admitted", w.Code)
	}
	c.f.ToggleUnavailable(true)
	if w := postGeneration(c, path+"scope", requests[0]); w.Code != 503 {
		t.Fatal("scope retry bypassed outage")
	}
}

func TestCurrentObservationClosedValidation(t *testing.T) {
	zero := ZeroCurrentObservation()
	if zero.Validate() != nil {
		t.Fatal("invalid zero")
	}
	variants := []CurrentObservation{zero, zero, zero, zero, zero}
	variants[0].FullAcceptance = true
	variants[1].AcceptedFrames = 1
	variants[2].Sources[0].Rows = 1
	variants[3].Sources[0].Scope = "other"
	variants[4].LastSequence = 1 << 53
	for _, o := range variants {
		if o.Validate() == nil || o.Ready() {
			t.Fatal("forged evidence accepted")
		}
	}
}
