package main

import (
	"context"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureV2FramingImpactAndSingleFakeDispatch(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1-default", true: "v2-explicit"}[v2], func(t *testing.T) {
			dir := t.TempDir()
			issuer, err := makeIssuer(time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://127.0.0.1:19899", CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()})
			cfg.RecordLimit = 25
			cfg.InvitationLimit = 25
			cfg.PendingLimit = 25
			state, err := enrollmentstore.Open(filepath.Join(dir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			ctx, cancel := context.WithCancel(context.Background())
			f := &fixture{serviceV2: v2, store: state, issuer: issuer, backend: &fakeBackend{serviceV2: v2, entered: make(chan struct{}), allowCompletion: make(chan struct{})}, context: ctx, cancel: cancel, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}}
			defer f.close()
			f.service, err = enrollmentservice.New(state, issuer, f.now)
			if err != nil {
				t.Fatal(err)
			}
			f.identity = f.seed()
			f.prepareActions(dir)
			server := httptest.NewUnstartedServer(nil)
			defer server.Close()
			f.agentOrigin = "http://" + server.Listener.Addr().String()
			ingress, err := enrollmenttransport.New(state, issuer.IssuerDER(), f.agentOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if err = ingress.ConfigureServiceActions(f.manager); err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = ingress
			server.Start()
			if err = f.refresh(); err != nil {
				t.Fatal(err)
			}
			record, _, err := f.manager.ViewAt(ctx, f.identity.Approval.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			if v2 {
				if record.Capabilities.Version != actionhelper.CapabilitiesVersionV2 || len(record.Capabilities.Services) != 1 || len(record.Capabilities.Services[0].AffectedServices) != 64 || len(record.Capabilities.ExcludedServices) != 1 {
					t.Fatal(record.Capabilities)
				}
				f.backend.excluded.Store(true)
				if err = f.refresh(); err != nil {
					t.Fatal(err)
				}
				record, _, err = f.manager.ViewAt(ctx, f.identity.Approval.DeviceID)
				if err != nil || len(record.Capabilities.Services) != 0 || len(record.Capabilities.ExcludedServices) != 2 {
					t.Fatal(err, record.Capabilities)
				}
				f.backend.excluded.Store(false)
				if err = f.refresh(); err != nil {
					t.Fatal(err)
				}
			} else if record.Capabilities.Version != actionhelper.CapabilitiesVersion || len(record.Capabilities.Services[0].AffectedServices) != 0 {
				t.Fatal("v1 broadened")
			}
			actor := "operator_00000000000000000000000000000001"
			record, err = f.manager.Preview(ctx, f.identity.Approval.DeviceID, actor, fixtureUnit)
			if err != nil {
				t.Fatal(err)
			}
			if v2 {
				digest, _ := actionpermit.AffectedServicesDigest(fixtureImpact())
				if record.Preview.Plan.AffectedServicesDigest != digest {
					t.Fatal("impact omitted")
				}
			}
			p := record.Preview
			if _, err = f.manager.Approve(ctx, f.identity.Approval.DeviceID, p.ID, p.Digest, actor); err != nil {
				t.Fatal(err)
			}
			if err = f.dispatch(); err != nil {
				t.Fatal(err)
			}
			if f.backend.calls.Load() != 1 {
				t.Fatal("no single fake dispatch")
			}
			if err = f.complete(); err != nil {
				t.Fatal(err)
			}
			if f.backend.calls.Load() != 1 || f.claims.Load() != 1 {
				t.Fatal("replayed fake execution")
			}
		})
	}
}
