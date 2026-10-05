package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/actionwire"
)

func (f *fixture) prepareActions(dir string) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	defer clear(key)
	must(f.store.InitializeServiceActions(f.context, pub))
	must(f.store.InitializeServiceActionIdentity(f.context, pub, f.identity.Approval.DeviceID, f.now()))
	keyPath := filepath.Join(dir, "invented-command.key")
	must(os.WriteFile(keyPath, key, 0600))
	cfg := actionmanager.Config{Version: actionmanager.ConfigVersion, Enabled: true, ManagerID: f.store.Config().Binding.InstanceID, TransportProfile: actionhelper.DisposableHTTPTest, HTTPTestAcknowledged: true, PrivateKeyFile: keyPath}
	configPath := filepath.Join(dir, "invented-actions.json")
	must(os.WriteFile(configPath, jsonBytes(cfg), 0600))
	root, e := x509.ParseCertificate(f.issuer.RootDER())
	must(e)
	issuer, e := x509.ParseCertificate(f.issuer.IssuerDER())
	must(e)
	f.manager, e = actionmanager.Load(f.context, f.store, configPath, root.PublicKey.(ed25519.PublicKey), issuer.PublicKey.(ed25519.PublicKey))
	must(e)
	target := actionhelper.Target{Unit: fixtureUnit, ReviewDigest: actionpermit.Digest([]byte("invented fixture review; no host inspection")), Units: []actionhelper.UnitPin{{Unit: fixtureUnit, ConfigurationDigest: actionpermit.Digest([]byte("invented fixture configuration"))}}, Inputs: []actionhelper.FilePin{{Path: "/usr/bin/systemctl", Digest: actionpermit.Digest([]byte("never read or executed in fixture"))}}}
	policy := actionhelper.Policy{Version: actionhelper.PolicyVersion, Enabled: true, ManagerID: cfg.ManagerID, KeyID: actionpermit.Digest(pub), EndpointID: f.identity.Approval.DeviceID, IncarnationDigest: "sha256:" + f.identity.Issuance.CertificateHash, TransportProfile: cfg.TransportProfile, HTTPTestAcknowledged: true, AgentUID: 1001, AgentGID: 1001, MaxLifetimeSeconds: 60, MaxFutureSkewSeconds: 5, Targets: []actionhelper.Target{target}}
	verifier, e := actionpermit.NewVerifier(actionpermit.LocalPins{Enabled: true, ManagerID: policy.ManagerID, PublicKey: pub, EndpointID: policy.EndpointID, IncarnationDigest: policy.IncarnationDigest, RootPolicyDigest: actionpermit.Digest(jsonBytes(policy)), MaxLifetimeSeconds: 60, MaxFutureSkewSeconds: 5, Services: []actionpermit.ServiceRule{{Unit: fixtureUnit, UnitPolicyDigest: actionpermit.Digest(jsonBytes(target))}}})
	must(e)
	f.helperState, e = actionstate.Initialize(f.context, filepath.Join(dir, "invented-helper-ledger"), verifier)
	must(e)
	authority := actionhelper.Authority{Policy: policy, PublicKey: pub, Revision: actionpermit.Digest([]byte("invented protected authority; not native root proof"))}
	f.helper, e = actionhelper.New(actionhelper.Dependencies{Load: func() (actionhelper.Authority, error) { return authority, nil }, Identity: func() error { return nil }, Peer: func(net.Conn) (actionhelper.Peer, error) {
		return actionhelper.Peer{UID: 1001, GID: 1001, PID: 99}, nil
	}, Backend: f.backend, State: f.helperState, Now: f.now})
	must(e)
}

// This deliberately uses the real bounded IPC codec/ServeConn over net.Pipe.
// Fake peer/root authority exist only in this loopback test executable; native
// kernel credentials and installed-root behavior are separate acceptance gates.
func (f *fixture) helperExchange(ctx context.Context, request actionhelper.Request) (actionhelper.Response, error) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); f.helper.ServeConn(ctx, server) }()
	defer func() { client.Close(); <-done }()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	if e := client.SetDeadline(f.now().Add(50 * time.Second)); e != nil {
		return actionhelper.Response{}, e
	}
	raw, e := actionhelper.EncodeRequest(request)
	if e != nil {
		return actionhelper.Response{}, e
	}
	for len(raw) > 0 {
		n, e := client.Write(raw)
		if e != nil || n <= 0 {
			return actionhelper.Response{}, errors.New("fixture_ipc_write")
		}
		raw = raw[n:]
	}
	result, e := actionhelper.ReadResponse(client)
	if e != nil {
		return actionhelper.Response{}, e
	}
	var extra [1]byte
	if n, e := client.Read(extra[:]); n != 0 || e != io.EOF {
		return actionhelper.Response{}, errors.New("fixture_ipc_trailing")
	}
	return result, nil
}
func (f *fixture) agentRequest(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
	r, e := actionwire.NewSignedRequest(ctx, f.agentOrigin, path, f.certificate, sequence, f.now(), body)
	if e != nil {
		return nil, 0, e
	}
	response, e := f.client.Do(r)
	if e != nil {
		return nil, 0, e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, actionwire.MaxBodyBytes+1))
	if e != nil || len(raw) > actionwire.MaxBodyBytes {
		return nil, 0, errors.New("fixture_response_bound")
	}
	return raw, response.StatusCode, nil
}
func (f *fixture) refresh() error {
	ctx, cancel := context.WithTimeout(f.context, 8*time.Second)
	defer cancel()
	r, e := f.helperExchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation})
	if e != nil || r.Capabilities == nil || r.Error != "" {
		return errors.New("fixture_capabilities")
	}
	body, e := actionwire.EncodeCapabilities(*r.Capabilities)
	if e != nil {
		return e
	}
	raw, code, e := f.agentRequest(ctx, actionwire.CapabilitiesPath, 1, body)
	if e != nil || code != 200 || actionwire.DecodePeek(raw) != nil {
		return errors.New("fixture_report")
	}
	return nil
}
func (f *fixture) dispatch() error {
	if f.dispatchStarted {
		return errors.New("fixture_dispatch_once")
	}
	ctx, cancel := context.WithTimeout(f.context, 8*time.Second)
	defer cancel()
	body, _ := actionwire.EncodePeek()
	raw, code, e := f.agentRequest(ctx, actionwire.PeekPath, 1, body)
	if e != nil || code != http.StatusOK {
		return errors.New("fixture_peek")
	}
	d, e := actionwire.DecodeDelivery(raw)
	if e != nil || d.State != actionjob.Approved {
		return errors.New("fixture_new_delivery_required")
	}
	body, e = actionwire.EncodeClaim(d.Identity)
	if e != nil {
		return e
	}
	raw, code, e = f.agentRequest(ctx, actionwire.ClaimPath, d.Identity.Sequence, body)
	if e != nil || code != http.StatusOK {
		return errors.New("fixture_claim")
	}
	grant, e := actionwire.DecodeGrant(raw)
	if e != nil || grant.Identity != d.Identity {
		return errors.New("fixture_grant")
	}
	f.claims.Add(1)
	f.dispatchStarted = true
	f.resultDone = make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(f.context, 45*time.Second)
		defer cancel()
		r, e := f.helperExchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: grant.Envelope})
		if e == nil {
			e = f.reportResult(ctx, grant.Identity, r)
		}
		f.resultDone <- e
	}()
	select {
	case <-f.backend.entered:
		return nil
	case e := <-f.resultDone:
		if e != nil {
			return e
		}
		return errors.New("fixture_did_not_invoke")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fixture) reportResult(ctx context.Context, i actionjob.Identity, r actionhelper.Response) error {
	if r.Result == nil || r.Result.JobID != i.JobID || r.Result.Sequence != i.Sequence || r.Result.EnvelopeDigest != i.EnvelopeDigest {
		return errors.New("fixture_result_identity")
	}
	body, e := actionwire.EncodeResult(*r.Result)
	if e != nil {
		return e
	}
	raw, code, e := f.agentRequest(ctx, actionwire.ResultPath, i.Sequence, body)
	if e != nil || code != http.StatusOK || actionwire.DecodePeek(raw) != nil {
		return errors.New("fixture_result_ingress")
	}
	return nil
}
func (f *fixture) complete() error {
	if !f.dispatchStarted || f.resultDone == nil {
		return errors.New("fixture_no_dispatch")
	}
	f.backend.release.Do(func() { close(f.backend.allowCompletion) })
	select {
	case e := <-f.resultDone:
		f.resultDone = nil
		return e
	case <-time.After(8 * time.Second):
		return errors.New("fixture_result_timeout")
	}
}
func (f *fixture) recoverStatus() error {
	ctx, cancel := context.WithTimeout(f.context, 8*time.Second)
	defer cancel()
	body, _ := actionwire.EncodePeek()
	raw, code, e := f.agentRequest(ctx, actionwire.PeekPath, 1, body)
	if e != nil {
		return e
	}
	if code == http.StatusNotFound {
		f.recoveryPeekStatus = "not_found"
		return nil
	}
	if code != http.StatusOK {
		return errors.New("fixture_recovery_peek")
	}
	d, e := actionwire.DecodeDelivery(raw)
	if e != nil || d.State != actionjob.Claimed {
		return errors.New("fixture_recovery_claimed_only")
	}
	f.recoveryPeekStatus = "claimed"
	r, e := f.helperExchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.StatusOperation, JobID: d.Identity.JobID})
	if e != nil {
		return e
	}
	return f.reportResult(ctx, d.Identity, r)
}
