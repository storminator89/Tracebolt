package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/actionwire"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type actionFakeBackend struct{ calls atomic.Int32 }

func (*actionFakeBackend) Check(context.Context, actionhelper.Target) (actionhelper.Observation, error) {
	return actionhelper.Active, nil
}
func (f *actionFakeBackend) TryRestart(context.Context, string) error { f.calls.Add(1); return nil }
func (*actionFakeBackend) Observe(context.Context, string) (actionhelper.Observation, error) {
	return actionhelper.Active, nil
}
func prepareActions(t *testing.T, f *fixture, h *Ingress) (*actionmanager.Manager, *actionhelper.Server, *actionFakeBackend, actionhelper.Peer) {
	t.Helper()
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{87}, 32))
	pub := key.Public().(ed25519.PublicKey)
	if e := f.store.InitializeServiceActions(ctx, pub); e != nil {
		t.Fatal(e)
	}
	if e := f.store.InitializeServiceActionIdentity(ctx, pub, f.snapshot.Approval.DeviceID, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	kp := filepath.Join(dir, "command.key")
	os.WriteFile(kp, key, 0600)
	cfg := actionmanager.Config{Version: actionmanager.ConfigVersion, Enabled: true, ManagerID: f.config.Binding.InstanceID, TransportProfile: actionmanager.Profile(f.config.Binding.Profile), HTTPTestAcknowledged: f.config.Binding.Profile == "http-test", PrivateKeyFile: kp}
	b, _ := json.Marshal(cfg)
	cp := filepath.Join(dir, "actions.json")
	os.WriteFile(cp, b, 0600)
	manager, e := actionmanager.Load(ctx, f.store, cp)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(manager.Close)
	if e = h.ConfigureServiceActions(manager); e != nil {
		t.Fatal(e)
	}
	target := actionhelper.Target{Unit: "fixture.service", ReviewDigest: actionpermit.Digest([]byte("fixture review")), Units: []actionhelper.UnitPin{{Unit: "fixture.service", ConfigurationDigest: actionpermit.Digest([]byte("fixture configuration"))}}, Inputs: []actionhelper.FilePin{{Path: "/usr/bin/systemctl", Digest: actionpermit.Digest([]byte("never read or executed"))}}}
	p := actionhelper.Policy{Version: actionhelper.PolicyVersion, Enabled: true, ManagerID: cfg.ManagerID, KeyID: actionpermit.Digest(pub), EndpointID: f.snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + f.cert.CertificateHash(), TransportProfile: cfg.TransportProfile, HTTPTestAcknowledged: cfg.HTTPTestAcknowledged, AgentUID: 1001, AgentGID: 1001, MaxLifetimeSeconds: 60, MaxFutureSkewSeconds: 5, Targets: []actionhelper.Target{target}}
	policyRaw, _ := json.Marshal(p)
	targetRaw, _ := json.Marshal(target)
	verifier, e := actionpermit.NewVerifier(actionpermit.LocalPins{Enabled: true, ManagerID: p.ManagerID, PublicKey: pub, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: actionpermit.Digest(policyRaw), MaxLifetimeSeconds: 60, MaxFutureSkewSeconds: 5, Services: []actionpermit.ServiceRule{{Unit: target.Unit, UnitPolicyDigest: actionpermit.Digest(targetRaw)}}})
	if e != nil {
		t.Fatal(e)
	}
	state, e := actionstate.Initialize(ctx, filepath.Join(dir, "helper-state"), verifier)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { state.Close() })
	authority := actionhelper.Authority{Policy: p, PublicKey: pub, Revision: actionpermit.Digest([]byte("fixture protected authority"))}
	backend := &actionFakeBackend{}
	peer := actionhelper.Peer{UID: 1001, GID: 1001, PID: 99}
	helper, e := actionhelper.New(actionhelper.Dependencies{Load: func() (actionhelper.Authority, error) { return authority, nil }, Identity: func() error { return nil }, Peer: func(net.Conn) (actionhelper.Peer, error) { return peer, nil }, Backend: backend, State: state, Now: func() time.Time { return time.Now().UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	return manager, helper, backend, peer
}
func (f *fixture) actionRequest(t *testing.T, origin, path string, seq uint64, body []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := actionwire.NewSignedRequest(context.Background(), origin, path, f.pair, seq, time.Now().UTC(), body)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest("POST", origin+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

type actionOperator struct {
	handler         http.Handler
	session         operatorauth.Session
	auth            *operatorauth.Manager
	origin, profile string
}

func actionOperatorNew(t *testing.T, f *fixture, manager *actionmanager.Manager, grant bool) *actionOperator {
	t.Helper()
	ctx := context.Background()
	service, e := enrollmentservice.New(f.store, f.issuer, nil)
	if e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(filepath.Join(t.TempDir(), "operator.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	app, e := api.New(db, 8787, t.TempDir(), model.Device{})
	if e != nil {
		t.Fatal(e)
	}
	capabilities := []operatorauth.Capability{operatorauth.Read}
	if grant {
		capabilities = append(capabilities, operatorauth.RestartService)
	}
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: id("operator", 17), Username: "maintainer", PasswordHash: journalFixturePasswordHash(), Capabilities: capabilities}}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.LoginNamed(ctx, "127.0.0.1", "maintainer", "invented-journal-password")
	if e != nil {
		t.Fatal(e)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})
	registry, e := lantrust.NewRegistry(ctx, root, lantrust.NewMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	origin := f.config.Binding.Origin
	bootstrap := api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: f.config.Binding.InstanceID, Profile: f.config.Binding.Profile, EnrollmentOrigin: origin, AgentOrigin: origin, CollectionProfile: f.config.Binding.CollectionProfile, IssuerRootPEM: string(root), IssuerPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.IssuerDER()}))}
	if f.config.Binding.Profile == "tls" {
		bootstrap.ServerCAPEM = string(root)
	}
	handler, e := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return service.Devices(ctx, time.Now().UTC()) }, InsecureHTTPTest: f.config.Binding.Profile == "http-test", Enrollment: service, EnrollmentBootstrap: bootstrap, ServiceActions: manager})
	if e != nil {
		t.Fatal(e)
	}
	return &actionOperator{handler, session, auth, origin, f.config.Binding.Profile}
}
func (o *actionOperator) call(t *testing.T, method, path string, input any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if input != nil {
		raw, _ = json.Marshal(input)
	}
	r := httptest.NewRequest(method, o.origin+path, bytes.NewReader(raw))
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", o.origin)
		r.Header.Set("X-CSRF-Token", o.session.CSRFToken)
	}
	name := operatorauth.CookieName
	if o.profile == "http-test" {
		name = "tracebolt-http-test-session"
	} else {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	}
	r.AddCookie(&http.Cookie{Name: name, Value: o.session.Token})
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	o.handler.ServeHTTP(w, r)
	return w
}
func TestServiceActionApprovedTransportToFakeHelperAndDurableResult(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			h, server, client := f.listen(t, nil)
			manager, helper, backend, peer := prepareActions(t, f, h)
			o := actionOperatorNew(t, f, manager, true)
			path := "/api/devices/" + f.snapshot.Approval.DeviceID + "/service-actions"
			caps, e := helper.Capabilities(context.Background(), peer)
			if e != nil {
				t.Fatal(e)
			}
			body, _ := actionwire.EncodeCapabilities(caps)
			response(t, client, f.actionRequest(t, server.URL, actionwire.CapabilitiesPath, 1, body), 200)
			forbidden := o.call(t, "POST", path+"/preview", map[string]string{"unit": "fixture.service"}, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") })
			if forbidden.Code != 403 {
				t.Fatal("CSRF guard", forbidden.Code)
			}
			injected := o.call(t, "POST", path+"/preview", map[string]string{"unit": "fixture.service", "actorId": id("operator", 18)}, nil)
			if injected.Code != 400 {
				t.Fatal("request actor accepted", injected.Code)
			}
			readOnly := actionOperatorNew(t, f, manager, false)
			if w := readOnly.call(t, "POST", path+"/preview", map[string]string{"unit": "fixture.service"}, nil); w.Code != 403 {
				t.Fatal("read account mutation", w.Code)
			}
			w := o.call(t, "POST", path+"/preview", map[string]string{"unit": "fixture.service"}, nil)
			if w.Code != 200 {
				t.Fatal("preview", w.Code, w.Body.String())
			}
			var view struct {
				Preview *actionjob.Preview `json:"preview"`
				Job     *struct {
					ID      string `json:"id"`
					State   string `json:"state"`
					ActorID string `json:"actorId"`
					Result  *struct {
						Phase         string `json:"phase"`
						ObservedState string `json:"observedState"`
					} `json:"result"`
				} `json:"job"`
			}
			if json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Preview == nil || view.Preview.ActorID != o.session.ActorID() {
				t.Fatal("preview actor")
			}
			p := *view.Preview
			approval := map[string]string{"previewId": p.ID, "previewDigest": p.Digest}
			w = o.call(t, "POST", path+"/approve", approval, nil)
			if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(`"envelope"`)) {
				t.Fatal("approval authority exposure", w.Code, w.Body.String())
			}
			if json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Job == nil || view.Job.State != actionjob.Approved || view.Job.ActorID != o.session.ActorID() {
				t.Fatal("approval result")
			}
			w = o.call(t, "POST", path+"/approve", approval, nil)
			if w.Code != 200 {
				t.Fatal("idempotent approval", w.Code)
			}
			peek, _ := actionwire.EncodePeek()
			raw := response(t, client, f.actionRequest(t, server.URL, actionwire.PeekPath, 1, peek), 200)
			if bytes.Contains(raw, []byte(`"envelope"`)) {
				t.Fatal("peek authority exposure")
			}
			delivery, e := actionwire.DecodeDelivery(raw)
			if e != nil || delivery.Identity.JobID != p.ID {
				t.Fatal("peek", e)
			}
			claim, _ := actionwire.EncodeClaim(delivery.Identity)
			raw = response(t, client, f.actionRequest(t, server.URL, actionwire.ClaimPath, delivery.Identity.Sequence, claim), 200)
			grant, e := actionwire.DecodeGrant(raw)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, f.actionRequest(t, server.URL, actionwire.ClaimPath, delivery.Identity.Sequence, claim), 409)
			raw = response(t, client, f.actionRequest(t, server.URL, actionwire.PeekPath, 1, peek), 200)
			claimed, e := actionwire.DecodeDelivery(raw)
			if e != nil || claimed.State != actionjob.Claimed {
				t.Fatal("status-only claimed peek")
			}
			st, e := helper.Handle(context.Background(), peer, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: grant.Envelope})
			if e != nil || st.Phase != actionstate.OperationCompleted || backend.calls.Load() != 1 {
				t.Fatal("fake helper outcome", e, st.Phase)
			}
			again, e := helper.Handle(context.Background(), peer, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.StatusOperation, JobID: p.ID})
			if e != nil || again.Phase != st.Phase || backend.calls.Load() != 1 {
				t.Fatal("status replay")
			}
			result := actionhelper.Result{JobID: p.ID, Sequence: p.Sequence, EnvelopeDigest: grant.Identity.EnvelopeDigest, Phase: st.Phase, ConsumedAt: st.ConsumedAt.UnixMicro(), DispatchAt: st.DispatchAt.UnixMicro(), TransitionAt: st.TransitionAt.UnixMicro(), Outcome: st.Outcome, ObservedState: st.ObservedState}
			body, e = actionwire.EncodeResult(result)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, f.actionRequest(t, server.URL, actionwire.ResultPath, p.Sequence, body), 200)
			response(t, client, f.actionRequest(t, server.URL, actionwire.ResultPath, p.Sequence, body), 200)
			w = o.call(t, "GET", path, nil, nil)
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Job == nil || view.Job.Result == nil || view.Job.State != actionstate.OperationCompleted || view.Job.Result.ObservedState != "active" || bytes.Contains(w.Body.Bytes(), []byte(`"envelope"`)) {
				t.Fatal("durable operator status", w.Code, w.Body.String())
			}
			record, e := manager.View(context.Background(), f.snapshot.Approval.DeviceID)
			if e != nil || len(record.Jobs) != 1 || len(record.Jobs[0].Results) != 1 || backend.calls.Load() != 1 {
				t.Fatal("duplicate created effect", e)
			}
			response(t, client, f.actionRequest(t, server.URL, actionwire.PeekPath, 1, peek), 404)
			f.revoke(t)
			response(t, client, f.actionRequest(t, server.URL, actionwire.ResultPath, p.Sequence, body), 403)
		})
	}
}
