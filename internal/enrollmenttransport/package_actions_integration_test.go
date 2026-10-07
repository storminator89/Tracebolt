//go:build linux

package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packagewire"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativePackageEnrolledTransportExactClaimsAndResults(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			h, server, client := f.listen(t, nil)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{83}, 32))
			dir := filepath.Join(t.TempDir(), "private")
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			c := packagecontroller.Config{Version: packagecontroller.ConfigVersion, Enabled: true, ManagerID: f.config.Binding.InstanceID, EndpointID: f.snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + f.cert.CertificateHash(), RootPolicyDigest: actionpermit.Digest([]byte("fixture protected package grant")), TransportProfile: map[string]string{"tls": "production-tls", "http-test": "disposable-http-test"}[profile], HTTPTestAcknowledged: profile == "http-test", StateFile: filepath.Join(dir, "jobs.sqlite"), PrivateKeyFile: filepath.Join(dir, "command.key"), LocalScopeAcknowledged: true}
			if e := os.WriteFile(c.PrivateKeyFile, key, 0600); e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(c)
			cp := filepath.Join(dir, "manager.json")
			if e := os.WriteFile(cp, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e := packagecontroller.Initialize(ctx, cp, true, now); e != nil {
				t.Fatal(e)
			}
			actor := id("operator", 17)
			m, e := packagecontroller.Load(ctx, cp, f.store.AuthorizePackageDevice, func(a string, cap operatorauth.Capability) bool {
				return a == actor && (cap == operatorauth.PlanUpdates || cap == operatorauth.ExecuteUpdates)
			})
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			if e = h.ConfigurePackageActions(m); e != nil {
				t.Fatal(e)
			}
			request := func(path string, seq uint64, body []byte) *http.Request {
				t.Helper()
				if profile == "http-test" {
					r, e := packagewire.NewSignedRequest(ctx, server.URL, path, f.pair, seq, time.Now().UTC(), body)
					if e != nil {
						t.Fatal(e)
					}
					return r
				}
				r, e := http.NewRequest("POST", server.URL+path, bytes.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				r.Header.Set("Content-Type", "application/json")
				return r
			}
			caps := packagehelper.Capabilities{Version: packagehelper.CapabilitiesVersion, Enabled: true, ManagerID: c.ManagerID, EndpointID: c.EndpointID, IncarnationDigest: c.IncarnationDigest, RootPolicyDigest: c.RootPolicyDigest, KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), TransportProfile: c.TransportProfile, HTTPTestAcknowledged: c.HTTPTestAcknowledged, CapturedAt: now.Unix(), Allowed: []packagepermit.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
			raw, e = packagewire.EncodeCapabilities(caps)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, request(packagewire.CapabilitiesPath, 1, raw), 200)
			req := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
			if e = m.Prepare(ctx, c.EndpointID, actor, req); e != nil {
				t.Fatal(e)
			}
			raw, _ = packagewire.EncodePeek()
			reply := response(t, client, request(packagewire.PeekPath, 1, raw), 200)
			d, e := packagewire.DecodeDelivery(reply)
			if e != nil || d.State != "pending" {
				t.Fatal(d, e)
			}
			raw, _ = packagewire.EncodeClaim(d.Identity)
			reply = response(t, client, request(packagewire.ClaimPath, 1, raw), 200)
			g, e := packagewire.DecodeGrant(reply)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, request(packagewire.ClaimPath, 1, raw), 409)
			permit, _, e := packagepermit.Decode(ctx, g.Envelope)
			if e != nil || permit.Action != packagepermit.Prepare || permit.ActorID != actor {
				t.Fatal("wrong signed preparation", e)
			}
			raw, e = os.ReadFile("../packageplan/testdata/plan.json")
			if e != nil {
				t.Fatal(e)
			}
			p, e := packageplan.Decode(ctx, raw)
			if e != nil {
				t.Fatal(e)
			}
			p.EndpointID = c.EndpointID
			p.IncarnationDigest = c.IncarnationDigest
			p.RootPolicyDigest = c.RootPolicyDigest
			preparedAt := time.Now().UTC().Unix()
			p.CreatedAt = preparedAt
			p.ExpiresAt = preparedAt + 60
			p.Evidence.InventoryAt = preparedAt
			p.Evidence.MetadataRefreshedAt = preparedAt
			preview, e := packageupdate.DescribePreview(ctx, c.Binding(), req, actor, p, []packageupdate.Source{{IdentityDigest: p.Packages[0].Archive.SourceIdentityDigest, Label: "Synthetic fixture repository", Suite: "trixie", Component: "main"}})
			if e != nil {
				t.Fatal(e)
			}
			snapshot := packagehelper.Snapshot{Version: packagehelper.SnapshotVersion, JobID: req.RequestID, Sequence: 1, PreparationEnvelopeDigest: actionpermit.Digest(g.Envelope), State: packageupdate.PreviewReady, Preview: &preview, Results: []packageupdate.Result{}, UpdatedAt: preparedAt}
			raw, e = packagewire.EncodeResult(snapshot)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, request(packagewire.ResultPath, 1, raw), 200)
			if e = m.Approve(ctx, c.EndpointID, actor, packageupdate.ApprovalRequest{RequestID: req.RequestID, PreviewDigest: preview.Digest}); e != nil {
				t.Fatal(e)
			}
			raw, _ = packagewire.EncodePeek()
			reply = response(t, client, request(packagewire.PeekPath, 1, raw), 200)
			d, e = packagewire.DecodeDelivery(reply)
			if e != nil || d.Identity.Kind != packagepermit.Execute {
				t.Fatal(d, e)
			}
			raw, _ = packagewire.EncodeClaim(d.Identity)
			reply = response(t, client, request(packagewire.ClaimPath, 1, raw), 200)
			g, e = packagewire.DecodeGrant(reply)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, request(packagewire.ClaimPath, 1, raw), 409)
			permit, _, e = packagepermit.Decode(ctx, g.Envelope)
			if e != nil || permit.PreviewDigest != preview.Digest || permit.PlanDigest != preview.PlanDigest || permit.Plan.Packages[0].To.Version != "1.0-2" {
				t.Fatal("exact approved authority lost", e)
			}
			snapshot.State = packageupdate.NeedsIntervention
			snapshot.ExecutionEnvelopeDigest = actionpermit.Digest(g.Envelope)
			observed := time.Now().UTC().Unix()
			snapshot.UpdatedAt = observed
			snapshot.Results = []packageupdate.Result{{Sequence: 1, Phase: packageupdate.NeedsIntervention, ObservedAt: observed, Reason: "runner_state_unknown", DpkgState: "unknown", Reboot: packageupdate.RebootEvidence{Source: "native", State: "unknown", ObservedAt: observed}, Packages: []packageupdate.PackageResult{{Name: "sample-bin", Architecture: "amd64", ExpectedVersion: "1.0-2", Outcome: "unknown"}}}}
			snapshot.Result = &snapshot.Results[0]
			raw, e = packagewire.EncodeResult(snapshot)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, request(packagewire.ResultPath, 1, raw), 200)
			view, e := m.View(ctx, c.EndpointID, time.Now().UTC())
			if e != nil || view.Job.State != packageupdate.NeedsIntervention || view.Available || view.Job.Result.Reboot.Source != "native" {
				t.Fatal(view, e)
			}
		})
	}
}
