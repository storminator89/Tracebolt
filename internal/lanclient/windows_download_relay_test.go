//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The sender, authenticated in-process ingress, enrollment-owned manager and
// signed IPC peer seam run without a listener. The actual executor/fence and
// retirement-to-install lifecycle is exercised by the domain integration test.
type downloadSavedPeer struct {
	scheduledSavedPeer
	managerKey ed25519.PublicKey
	result     []byte
}

func (p *downloadSavedPeer) Readiness(_ context.Context, raw []byte) ([]byte, error) {
	c, e := job.VerifyChallenge(raw, p.managerKey)
	if e != nil || !c.Download() {
		return nil, job.ErrAuthority
	}
	if bytes.Equal(raw, p.challenge) {
		return nil, job.ErrConsumed
	}
	p.readiness++
	p.challenge = bytes.Clone(raw)
	r := p.ready
	r.CapturedAt = p.now().Unix()
	proof, e := job.SignStatement(job.Statement{Version: job.DownloadRelayVersion, Kind: "readiness", Binding: p.binding, JobID: c.JobID, ReferenceDigest: actionpermit.Digest(raw), Deadline: c.Deadline, IssuedAt: r.CapturedAt, ExpiresAt: min(r.CapturedAt+60, c.Deadline), Readiness: &r}, p.key)
	p.report = bytes.Clone(proof)
	return proof, e
}
func (p *downloadSavedPeer) Submit(_ context.Context, raw []byte) error {
	permit, e := job.Verify(raw, p.managerKey)
	if e != nil || !permit.Download() || p.submits != 0 {
		return job.ErrAuthority
	}
	p.submits++
	r := job.Result{Purpose: job.DownloadPurpose, JobID: permit.Preview.ID, EnvelopeDigest: actionpermit.Digest(raw), Attempted: true, NativeReturned: true, CleanupSucceeded: true, AggregateResultKnown: true, AggregateHResultKnown: true, UpdateResultKnown: true, UpdateHResultKnown: true, Outcome: "succeeded", AggregateOperationResult: 2, OperationResult: 2, RebootRequired: job.Unknown, DownloadedAfter: job.Yes, CompletedAt: p.now().Unix()}
	p.result, e = job.SignStatement(job.Statement{Version: job.DownloadRelayVersion, Kind: "result", Binding: p.binding, JobID: r.JobID, ReferenceDigest: r.EnvelopeDigest, Deadline: permit.Preview.ExpiresAt, IssuedAt: r.CompletedAt, ExpiresAt: r.CompletedAt + 300, Result: &r}, p.key)
	return e
}
func (p *downloadSavedPeer) Outbox(ctx context.Context, kind, id, digest string) ([]byte, error) {
	if kind == "result" && len(p.result) > 0 {
		s, e := job.VerifyStatement(p.result, p.key.Public().(ed25519.PublicKey))
		if e != nil || s.JobID != id || s.ReferenceDigest != digest {
			return nil, job.ErrConflict
		}
		return bytes.Clone(p.result), nil
	}
	return p.scheduledSavedPeer.Outbox(ctx, kind, id, digest)
}
func TestDownloadRelayUsesPurposeSeparatedClaimAndNeverRetriesLostDelivery(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprint(lost), func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
			ctx := context.Background()
			at := time.Now().UTC().Truncate(time.Second)
			clock := func() time.Time { return time.Now().UTC().Truncate(time.Second) }
			mk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32))
			ek := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{212}, 32))
			mp := mk.Public().(ed25519.PublicKey)
			ep := ek.Public().(ed25519.PublicKey)
			id := func(prefix string, c string) string { return prefix + strings.Repeat(c, 32) }
			b := job.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.material.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(f.material), ExecutorID: id("executor_", "7"), ExecutorKeyID: actionpermit.Digest(ep), GrantID: id("grant_", "6"), KeyID: actionpermit.Digest(mp)}
			mm := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{213}, 32)).Public().(ed25519.PublicKey)
			me := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{214}, 32)).Public().(ed25519.PublicKey)
			mb := msi.Binding{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest, ExecutorID: id("executor_", "4"), ExecutorKeyID: actionpermit.Digest(me), KeyID: actionpermit.Digest(mm), DeliveryGrantID: id("grant_", "4"), InstallGrantID: id("grant_", "5")}
			wb, _ := json.Marshal(b)
			mraw, _ := json.Marshal(mb)
			plan := actionpermit.Digest([]byte("fresh combined relay fixture"))
			grant := msi.Grant{Version: msi.ReusableGrantVersion, ReusableAcknowledged: true, MutationPlanDigest: plan, PeerBindingDigest: actionpermit.Digest(wb), Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: at.Unix() + 3600}
			if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, mm, me, grant, at, false); e != nil {
				t.Fatal(e)
			}
			consent := job.Consent{Version: job.DownloadConsentVersion, ReusableAcknowledged: true, BackgroundAcknowledged: true, DownloadScope: job.DownloadScope, DownloadAcknowledged: true, MutationPlanDigest: plan, PeerBindingDigest: actionpermit.Digest(mraw), Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: grant.ExpiresAt}
			if e := f.store.SetupWindowsUpdateJobsCreateOnly(ctx, mp, ep, consent, at); e != nil {
				t.Fatal(e)
			}
			manager, e := job.OpenTransactional(ctx, f.store, b, mk, clock)
			if e != nil {
				t.Fatal(e)
			}
			defer manager.Close()
			actor, jobID := id("operator_", "9"), id("update_", "8")
			if e = manager.ConfigureOperatorPolicy(func(a string) bool { return a == actor }); e != nil {
				t.Fatal(e)
			}
			if e = manager.ConfigureDownloadPolicy(func(a string) bool { return a == actor }); e != nil {
				t.Fatal(e)
			}
			peer := &downloadSavedPeer{managerKey: mp, scheduledSavedPeer: scheduledSavedPeer{now: clock, key: ek, binding: b, shared: fence.Status{Active: true, Phase: "idle", Revision: 1, Retained: 1}, ready: job.Readiness{Selection: job.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}, CapturedAt: at.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, BundledCount: 0, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "can", OfflineVerified: job.Yes}}}
			peer.ready.Purpose = job.DownloadPurpose
			peer.ready.Downloaded = job.No
			peer.ready.DownloadMetadataKnown = true
			peer.ready.DownloadOrigins = "https://download.invalid"
			peer.ready.DownloadMinBytes = 10
			peer.ready.DownloadMaxBytes = 20
			peer.ready.DownloadSource = "default"
			g := WindowsUpdateRelayGrant{Version: WindowsBackgroundUpdateRelayGrantVersion, Scope: WindowsUpdateRelayScope, Enabled: true, Acknowledged: true, SenderBinding: f.material.binding, ManagerOrigin: f.material.config.ManagerOrigin, Binding: b, ManagerPublicKey: mp, ExecutorPublicKey: ep, ExpiresAt: consent.ExpiresAt, ExecutorPeer: windowsupdateipc.PeerConfig{Version: windowsupdateipc.ServicePeerVersion, Binding: b, ExecutorPublicKey: ep, Executable: `C:\Program Files\Tracebolt\tracebolt-windows-update-service.exe`, ExecutableDigest: actionpermit.Digest([]byte("service image")), ConfigurationDigest: actionpermit.Digest([]byte("v5 exact config"))}}
			sender := openWindowsUpdateJobSender(f.material)
			defer sender.Close()
			sender.current = func(Material) bool { return true }
			sender.local = func(Material) (WindowsUpdateRelayGrant, error) { return g, nil }
			sender.now = clock
			sender.newExecutor = nil
			sender.executor = peer

			if e = f.ingress.ConfigureWindowsUpdateJobs(manager); e != nil {
				t.Fatal(e)
			}
			leaf, e := x509.ParseCertificate(f.material.certificate.Certificate[0])
			if e != nil {
				t.Fatal(e)
			}
			issuer, e := x509.ParseCertificate(f.issuer.IssuerDER())
			if e != nil {
				t.Fatal(e)
			}
			claims := 0
			sender.exchange = func(c context.Context, path string, body []byte) ([]byte, int, error) {
				r, e := http.NewRequestWithContext(c, http.MethodPost, f.config.Binding.Origin+path, bytes.NewReader(body))
				if e != nil {
					return nil, 0, e
				}
				r.Header.Set("Content-Type", "application/json")
				r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}
				w := httptest.NewRecorder()
				f.ingress.ServeHTTP(w, r)
				if strings.HasSuffix(path, "/download-claim") {
					claims++
					if lost {
						return nil, 0, job.ErrUncertain
					}
				}
				if strings.HasSuffix(path, "/install-claim") {
					t.Fatal("download relayed as install")
				}
				return w.Body.Bytes(), w.Code, nil
			}
			if e = manager.RequestDownload(ctx, b.DeviceID, actor, jobID, peer.ready.Selection); e != nil {
				t.Fatal(e)
			}
			if got := sender.Run(ctx); got != "reported" {
				t.Fatal("download readiness", got)
			}
			if got := sender.Run(ctx); got != "idle" {
				t.Fatal("shared status", got)
			}
			view, e := manager.View(ctx, b.DeviceID, actor)
			if e != nil || view.Job == nil || view.Job.Preview == nil {
				t.Fatal(e)
			}
			if e = manager.ApproveDownload(ctx, b.DeviceID, actor, jobID, view.Job.Preview.Digest, true); e != nil {
				t.Fatal(e)
			}
			got := sender.Run(ctx)
			if !lost && got != "reported" || lost && got != "outcome_unknown" {
				t.Fatal("download dispatch", got)
			}
			if got = sender.Run(ctx); got != "idle" {
				t.Fatal("terminal poll", got)
			}
			saved, e := f.store.ReadRegisteredWindowsUpdateJob(ctx, b, mp)
			if e != nil || claims != 1 || peer.readiness != 1 {
				t.Fatal("claim/readiness replay", claims, peer.readiness, e)
			}
			if lost {
				if peer.submits != 0 || saved.Jobs[0].State != "claimed" || saved.Jobs[0].Result != nil {
					t.Fatal("lost delivery manufactured result")
				}
			} else if peer.submits != 1 || saved.Jobs[0].State != "complete" || saved.Jobs[0].Result.Purpose != job.DownloadPurpose || saved.Jobs[0].Result.DownloadedAfter != job.Yes {
				t.Fatal("download result lost", saved.Jobs[0])
			}
		})
	}
}
