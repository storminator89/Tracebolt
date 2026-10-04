//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/api"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/store"
	"localrmm/internal/telemetry"
)

// All observations and model responses below are synthetic. Requests go only to
// owned loopback fixtures; no host collector, real model, or installer is used.
func operationalAPIHTTPFixture(t *testing.T, httpTest bool, collection string) (*independentEnrollmentHTTP, *store.Store) {
	t.Helper()
	h := independentEnrollmentHTTPNew(t, httpTest, false)
	cfg := h.f.store.Config()
	if err := h.f.store.Close(); err != nil {
		t.Fatal("fixture close failed")
	}
	cfg.Binding.CollectionProfile = collection
	h.f.path = filepath.Join(t.TempDir(), "private", "operations.sqlite")
	h.f.store = independentEnrollmentStoreOpen(t, h.f.path, cfg, h.f.issuer.IssuerDER())
	var err error
	h.f.service, err = enrollmentservice.New(h.f.store, h.f.issuer, h.f.clock)
	if err != nil {
		t.Fatal("fixture service failed")
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "ui.sqlite"))
	if err != nil {
		t.Fatal("fixture case store failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	h.app, err = api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal("fixture app failed")
	}
	h.config.Enrollment = h.f.service
	h.config.EnrollmentBootstrap.CollectionProfile = collection
	h.config.Devices = func() ([]model.Device, error) { return h.f.service.Devices(context.Background(), h.f.clock()) }
	h.handler, err = api.NewLANOperatorHandler(h.app, h.config)
	if err != nil {
		t.Fatal("fixture operational handler failed")
	}
	// No fixture requests are made before replacing its initial handler.
	h.server.Config.Handler = h.handler
	return h, db
}

func TestIndependentOperationalProfileConfigStrictAndImmutable(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newEnrollmentConfigFixture(t, transport)
			basic := f.load(t)
			if basic.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfile {
				t.Fatal("old config no longer defaults basic")
			}
			raw, _ := os.ReadFile(f.path)
			if bytes.Contains(raw, []byte("collectionProfile")) {
				t.Fatal("basic config wire shape expanded")
			}
			if err := basic.PrepareMode(f.lan.Config.StateDirectory, 0); err != nil {
				t.Fatal("basic marker creation failed")
			}
			markerPath := filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)
			before, _ := os.ReadFile(markerPath)
			root := sha256.Sum256(basic.Issuer().RootDER())
			trust := sha256.Sum256([]byte(basic.ServerCAPEM()))
			golden, _ := json.Marshal(struct{ SchemaVersion, Profile, InstanceID, OperatorOrigin, AgentOrigin, CollectionProfile, IssuerFingerprint, IssuerRootFingerprint, ServerTrustHash string }{"tracebolt.identity-mode.v2", transport, f.config.InstanceID, f.lan.Config.OperatorOrigin, f.lan.Config.AgentOrigin, "basic-readonly-v1", basic.Issuer().Fingerprint(), hex.EncodeToString(root[:]), hex.EncodeToString(trust[:])})
			if !bytes.Equal(before, golden) {
				t.Fatal("original basic marker bytes changed")
			}
			f.config.CollectionProfile = enrollmentcrypto.CollectionProfile
			f.save(t)
			if err := f.load(t).PrepareMode(f.lan.Config.StateDirectory, 0); err != nil {
				t.Fatal("explicit basic cannot reopen original marker")
			}
			f.config.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
			f.save(t)
			managed := f.load(t)
			if err := managed.PrepareMode(f.lan.Config.StateDirectory, 0); err == nil {
				t.Fatal("managed profile adopted basic state")
			}
			after, _ := os.ReadFile(markerPath)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected switch rewrote basic marker")
			}
			base, _ := os.ReadFile(f.path)
			for name, bad := range map[string][]byte{
				"null":      bytes.Replace(base, []byte(`"collectionProfile":"managed-operations-v1"`), []byte(`"collectionProfile":null`), 1),
				"case":      bytes.Replace(base, []byte(`"collectionProfile"`), []byte(`"CollectionProfile"`), 1),
				"duplicate": bytes.Replace(base, []byte(`"collectionProfile":"managed-operations-v1"`), []byte(`"collectionProfile":"managed-operations-v1","collectionProfile":"managed-operations-v1"`), 1),
				"unknown":   bytes.Replace(base, []byte(`"managed-operations-v1"`), []byte(`"managed-operations-v99"`), 1),
				"extra":     append([]byte(`{"enableAll":true,`), base[1:]...),
			} {
				t.Run(name, func(t *testing.T) {
					enrollmentConfigWrite(t, f.path, bad, 0644)
					if _, err := enrollmentconfig.Load(f.path, f.lan, f.now); err == nil {
						t.Fatal("ambiguous profile accepted")
					}
				})
			}
			f.lan.Config.StateDirectory = filepath.Join(t.TempDir(), "fresh")
			if os.Mkdir(f.lan.Config.StateDirectory, 0700) != nil {
				t.Fatal("fresh state fixture failed")
			}
			f.save(t)
			fresh := f.load(t)
			if fresh.StoreConfig().Binding.CollectionProfile != operational.CollectionProfile || fresh.PrepareMode(f.lan.Config.StateDirectory, 0) != nil {
				t.Fatal("fresh explicit operational profile rejected")
			}
			f.config.CollectionProfile = ""
			f.save(t)
			if f.load(t).PrepareMode(f.lan.Config.StateDirectory, 0) == nil {
				t.Fatal("operational marker returned to basic")
			}
		})
	}
}

func TestIndependentOperationalHTTPReadBoundary(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		name := "tls"
		if httpTest {
			name = "http-test"
		}
		t.Run(name, func(t *testing.T) {
			h, _ := operationalAPIHTTPFixture(t, httpTest, operational.CollectionProfile)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			path := "/api/devices/" + identity.Approval.DeviceID + "/operational"
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = http.MethodGet
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			code, body, _ := h.request(t, path, nil, read)
			var view enrollmentstore.OperationalView
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != "awaiting" || view.Snapshot != nil || !view.ServerNow.Equal(h.f.clock()) {
				t.Fatal("initial read did not preserve trusted awaiting state")
			}
			snapshot := operationalStoreSnapshot(h.f.clock(), "services")
			frame := operationalStoreFrame(t, 1, h.f.clock(), &snapshot)
			receipt, err := h.f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, frame, h.f.clock())
			if err != nil {
				t.Fatal("synthetic observation admission failed")
			}
			for n := 0; n < 2; n++ {
				code, body, _ = h.request(t, path, nil, read)
				if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != "fresh" || view.Snapshot == nil || view.Snapshot.GenerationID != snapshot.GenerationID || view.Sequence == nil || *view.Sequence != receipt.Sequence || view.ReceivedAt == nil || !view.ReceivedAt.Equal(receipt.ReceivedAt) {
					t.Fatal("GET changed or recollected observation")
				}
			}
			for name, change := range map[string]func(*http.Request){
				"no session":       func(r *http.Request) { r.Method = "GET" },
				"wrong host":       func(r *http.Request) { read(r); r.Host = "other.example" },
				"wrong origin":     func(r *http.Request) { read(r); r.Header.Set("Origin", "https://other.example") },
				"duplicate origin": func(r *http.Request) { read(r); r.Header.Add("Origin", h.origin); r.Header.Add("Origin", h.origin) },
				"cross site":       func(r *http.Request) { read(r); r.Header.Set("Sec-Fetch-Site", "cross-site") },
			} {
				code, _, _ := h.request(t, path, nil, change)
				want := 403
				if name == "no session" {
					want = 401
				}
				if code != want {
					t.Fatalf("%s guard returned %d, wanted %d", name, code, want)
				}
			}
			for _, badPath := range []string{path + "?fresh=true", strings.Replace(path, "/operational", "/%6fperational", 1)} {
				if code, _, _ := h.request(t, badPath, nil, read); code != 400 {
					t.Fatal("read accepted request-controlled interpretation")
				}
			}
			if code, _, _ := h.request(t, "/api/devices/agent_"+strings.Repeat("0", 32)+"/operational", nil, read); code != 404 {
				t.Fatal("unknown identity exposed")
			}
			for _, method := range []string{"HEAD", "PUT", "DELETE"} {
				if code, _, _ := h.request(t, path, nil, func(r *http.Request) { read(r); r.Method = method }); code != 405 {
					t.Fatal("unexpected read method admitted")
				}
			}
			before, _ := h.f.store.Get(context.Background(), identity.InvitationID)
			for _, missing := range []string{"Origin", "X-CSRF-Token"} {
				if code, _, _ := h.request(t, path, []byte(`{}`), func(r *http.Request) { h.browser(session)(r); r.Header.Del(missing) }); code != 403 {
					t.Fatal("POST omitted origin/CSRF")
				}
			}
			after, _ := h.f.store.Get(context.Background(), identity.InvitationID)
			if before != after {
				t.Fatal("operational API changed identity")
			}
			h.auth.Logout(session.Token)
			if code, _, _ := h.request(t, path, nil, read); code != 401 {
				t.Fatal("logged-out session read operations")
			}
		})
	}
}

func TestIndependentOperationalHTTPInvitationConsent(t *testing.T) {
	h, _ := operationalAPIHTTPFixture(t, true, operational.CollectionProfile)
	session := h.session(t)
	base := `{"requestId":"` + h.f.nextRequest() + `","platform":"linux"`
	for name, suffix := range map[string]string{
		"missing": `}`, "false": `,"collectionAcknowledged":false}`, "null": `,"collectionAcknowledged":null}`,
		"case": `,"CollectionAcknowledged":true}`, "string": `,"collectionAcknowledged":"true"}`,
		"duplicate":      `,"collectionAcknowledged":true,"collectionAcknowledged":true}`,
		"select profile": `,"collectionAcknowledged":true,"collectionProfile":"basic-readonly-v1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := h.request(t, "/api/enrollment/invitations", []byte(base+suffix), h.browser(session)); code != 400 {
				t.Fatal("invitation bypassed exact consent")
			}
		})
	}
	rows, err := h.f.store.Snapshots(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("rejected acknowledgement created invitation")
	}
	code, raw, _ := h.request(t, "/api/enrollment/invitations", []byte(base+`,"collectionAcknowledged":true}`), h.browser(session))
	var created struct {
		Snapshot  enrollmentstate.Snapshot `json:"snapshot"`
		Bootstrap api.EnrollmentBootstrap  `json:"bootstrap"`
	}
	if code != 201 || json.Unmarshal(raw, &created) != nil || created.Snapshot.Binding.CollectionProfile != operational.CollectionProfile || created.Bootstrap.CollectionProfile != operational.CollectionProfile {
		t.Fatal("accepted invitation lost selected profile")
	}
	changed := h.config
	changed.EnrollmentBootstrap.CollectionProfile = enrollmentcrypto.CollectionProfile
	if _, err := api.NewLANOperatorHandler(h.app, changed); err == nil {
		t.Fatal("bootstrap relabeled immutable operational service")
	}
}

func operationalAPIReviewCase(id, profile, evidenceProfile string) model.Case {
	now := time.Now().UTC()
	evidence := model.Evidence{ID: "synthetic-evidence", Title: "Synthetic observation", Source: "disposable fixture", Quality: "healthy", CollectedAt: now, Detail: "Fixed synthetic case text", Value: "fixture", Synthetic: true, CollectionProfile: evidenceProfile}
	return model.Case{ID: id, Title: "Synthetic case", Summary: "Fixed fixture summary", Category: "storage", RuleID: "test-rule", RunbookID: "none", CreatedAt: now, UpdatedAt: now, EvidenceIDs: []string{evidence.ID}, Evidence: []model.Evidence{evidence}, CollectionProfile: profile, Synthetic: true}
}

func TestIndependentOperationalHTTPAITrustedInstanceGate(t *testing.T) {
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, operational.CollectionProfile} {
		t.Run(profile, func(t *testing.T) {
			h, db := operationalAPIHTTPFixture(t, true, profile)
			session := h.session(t)
			var calls atomic.Int64
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				content := `{"observedEvidenceIDs":["synthetic-evidence"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"none"}`
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
			}))
			defer provider.Close()
			code, raw, _ := h.request(t, "/api/ai/config", nil, func(r *http.Request) { h.browser(session)(r); r.Method = "GET" })
			var config struct {
				Revision string `json:"revision"`
			}
			if code != 200 || json.Unmarshal(raw, &config) != nil {
				t.Fatal("AI config read failed")
			}
			settings, _ := json.Marshal(map[string]any{"expectedRevision": config.Revision, "baseURL": provider.URL + "/v1", "model": "synthetic-fixture", "apiKey": "", "approvedOrigin": provider.URL, "allowRemoteEvidence": false, "useLegacyMaxTokens": false})
			code, raw, _ = h.request(t, "/api/ai/config", settings, h.browser(session))
			if code != 200 || json.Unmarshal(raw, &config) != nil {
				t.Fatal("fake provider setup failed")
			}
			cases := []model.Case{operationalAPIReviewCase("untagged", "", ""), operationalAPIReviewCase("basic-tagged", enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfile), operationalAPIReviewCase("managed-tagged", operational.CollectionProfile, ""), operationalAPIReviewCase("mixed-evidence", "", operational.CollectionProfile)}
			if db.Seed(nil, cases) != nil {
				t.Fatal("distinct synthetic case seeds failed")
			}
			analyzeBody, _ := json.Marshal(map[string]string{"configRevision": config.Revision})
			for _, c := range cases {
				got, err := db.Case(c.ID)
				if err != nil || got.CollectionProfile != c.CollectionProfile || got.Evidence[0].CollectionProfile != c.Evidence[0].CollectionProfile {
					t.Fatal("case fixture provenance not persisted")
				}
				code, raw, _ := h.request(t, "/api/cases/"+c.ID+"/analyze", analyzeBody, h.browser(session))
				want := 403
				if profile == enrollmentcrypto.CollectionProfile {
					want = 422
					if c.ID == "untagged" || c.ID == "basic-tagged" {
						want = 200
					}
				}
				if code != want {
					t.Fatalf("%s analysis returned %d, wanted %d", c.ID, code, want)
				}
				if want != 200 && bytes.Contains(raw, []byte("Fixed fixture summary")) {
					t.Fatal("blocked analysis copied case text")
				}
			}
			if profile == operational.CollectionProfile {
				if db.Close() != nil {
					t.Fatal("closed case store fixture failed")
				}
				if code, _, _ := h.request(t, "/api/cases/untagged/analyze", analyzeBody, h.browser(session)); code != 403 {
					t.Fatal("managed gate loaded case text before trusted profile check")
				}
				if code, _, _ := h.request(t, "/api/cases/unknown/analyze", analyzeBody, h.browser(session)); code != 403 {
					t.Fatal("managed gate depended on case existence")
				}
				if calls.Load() != 0 {
					t.Fatal("managed source reached fake provider")
				}
			} else if calls.Load() != 2 {
				t.Fatal("mixed provenance reached fake provider or basic compatibility broke")
			}
		})
	}
}

func TestIndependentOperationalBasicTelemetryCompatibility(t *testing.T) {
	now := time.Now().UTC()
	var frame lanstore.Frame
	raw := operationalStoreFrame(t, 1, now, nil)
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("synthetic frame failed")
	}
	frame.Observation.Version = model.Version
	for _, id := range []string{"cpu", "memory", "disk", "os", "uptime", "host_inventory", "systemd", "journal", "remote_actions"} {
		status := "unsupported"
		if id == "host_inventory" {
			status = "limited"
		}
		frame.Observation.Observation.Capabilities = append(frame.Observation.Observation.Capabilities, model.Capability{ID: id, Name: "Synthetic fixture", Status: status, Detail: "Fixed disclosure"})
	}
	for _, id := range []string{"sandbox-cpu", "sandbox-memory", "sandbox-disk", "sandbox-os", "sandbox-uptime", "sandbox-scope"} {
		frame.Observation.Observation.Evidence = append(frame.Observation.Observation.Evidence, model.Evidence{ID: id, Title: "Fixture", Source: "disposable fixture", Quality: "unknown", CollectedAt: now})
	}
	raw, _ = json.Marshal(frame)
	if bytes.Contains(raw, []byte("collectionProfile")) {
		t.Fatal("basic frame expanded")
	}
	if _, err := lanstore.ValidateFrame(raw, now); err != nil {
		t.Fatal("ordinary basic frame evidence rejected")
	}
	body, _ := json.Marshal(frame.Observation)
	if _, err := telemetry.NewState().Accept(body, now); err != nil {
		t.Fatal("ordinary basic development evidence rejected")
	}
	for _, value := range []string{`"basic-readonly-v1"`, `"managed-operations-v1"`, `null`} {
		bad := bytes.Replace(body, []byte(`"id":"sandbox-cpu"`), []byte(`"id":"sandbox-cpu","collectionProfile":`+value), 1)
		if _, err := telemetry.NewState().Accept(bad, now); err == nil {
			t.Fatal("internal provenance accepted as old wire extension")
		}
	}
}

func TestIndependentOperationalFrameWireIsolation(t *testing.T) {
	at := time.Now().UTC()
	snapshot := operationalStoreSnapshot(at, "services")
	raw := operationalStoreFrame(t, 1, at, &snapshot)
	for name, alter := range map[string]func([]byte) []byte{
		"section case": func(b []byte) []byte { return bytes.Replace(b, []byte(`"services":`), []byte(`"Services":`), 1) },
		"field case":   func(b []byte) []byte { return bytes.Replace(b, []byte(`"durationMs":`), []byte(`"DurationMs":`), 1) },
		"null scalar": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"durationMs":0`), []byte(`"durationMs":null`), 1)
		},
		"null array": func(b []byte) []byte { return bytes.Replace(b, []byte(`"items":[]`), []byte(`"items":null`), 1) },
		"unknown field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"durationMs":0`), []byte(`"durationMs":0,"command":"fixture"`), 1)
		},
		"missing zero": func(b []byte) []byte { return bytes.Replace(b, []byte(`"durationMs":0,`), nil, 1) },
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"durationMs":0`), []byte(`"durationMs":0,"durationMs":0`), 1)
		},
		"profile case": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"managed-operations-v1"`), []byte(`"Managed-operations-v1"`), 1)
		},
		"unknown profile": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"managed-operations-v1"`), []byte(`"basic-readonly-v1"`), 1)
		},
		"old frame version": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"tracebolt.agent-telemetry.v2"`), []byte(`"tracebolt.agent-telemetry.v1"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := alter(bytes.Clone(raw))
			if bytes.Equal(raw, bad) {
				t.Fatal("mutation did not exercise intended boundary")
			}
			if _, err := lanstore.ValidateFrame(bad, at); err == nil {
				t.Fatal("ambiguous operational wire admitted")
			}
		})
	}
	f, err := lanstore.ValidateFrame(raw, at)
	if err != nil || !lanstore.FrameMatchesCollectionProfile(f, operational.CollectionProfile) || lanstore.FrameMatchesCollectionProfile(f, enrollmentcrypto.CollectionProfile) {
		t.Fatal("operational frame authorized against wrong trusted profile")
	}
	basic, err := lanstore.ValidateFrame(operationalStoreFrame(t, 1, at, nil), at)
	if err != nil || !lanstore.FrameMatchesCollectionProfile(basic, enrollmentcrypto.CollectionProfile) || lanstore.FrameMatchesCollectionProfile(basic, operational.CollectionProfile) {
		t.Fatal("basic frame authorized against operational identity")
	}
}
