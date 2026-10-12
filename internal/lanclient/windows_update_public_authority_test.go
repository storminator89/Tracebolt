//go:build linux

package lanclient

import (
	"context"
	"encoding/json"
	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"os"
	"strings"
	"testing"
	"time"
)

func publicUpdateFixture(t *testing.T) (*updateAuthorityFixture, windowsupdateipc.Config) {
	f := newUpdateAuthorityFixture(t)
	d := func(s string) string { return actionpermit.Digest([]byte(s)) }
	b := f.peer.Binding
	c := job.Consent{Version: job.BackgroundConsentVersion, BackgroundAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.grant.ExpiresAt, MutationPlanDigest: d("plan"), PeerBindingDigest: d("msi binding")}
	roster := fence.Roster{Version: fence.BackgroundRosterVersion, Plan: fence.Plan{Version: fence.BackgroundPlanVersion, Identity: fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}, PlanDigest: c.MutationPlanDigest, MSIOfferDigest: d("msi offer"), WUAOfferDigest: d("wua offer"), MSIArtifactDigest: d("msi artifact"), WUAArtifactDigest: d("wua artifact")}, FenceID: d("fence"), MSI: fence.Participant{Domain: fence.ManagedMSI, BindingDigest: c.PeerBindingDigest, GrantDigest: d("msi grant"), ManagerKeyDigest: d("msi key"), ExecutorKeyDigest: d("msi executor")}, WUA: job.MutationParticipant(c)}
	raw, _ := json.Marshal(f.current.config)
	config := windowsupdateipc.Config{Version: windowsupdateipc.ServiceConfigVersion, Mutation: &roster, Consent: c, ObserverConfigDigest: actionpermit.Digest(raw), SenderBinding: f.current.binding, ManagerOrigin: f.current.config.ManagerOrigin, ManagerPublicKey: f.grant.ManagerPublicKey, ExecutorPublicKey: f.grant.ExecutorPublicKey, Executable: `C:\Program Files\Tracebolt\tracebolt-windows-update-service.exe`, ExecutableDigest: d("image"), ObserverReceipt: windowsservice.Receipt{Version: 1, Complete: true, InstallationID: "fixture", ServiceSID: "S-1-5-80-1-2-3-4-5", Layout: f.layout}, ObserverProcessQueryAcknowledged: true}
	peer, e := config.Peer()
	if e != nil {
		t.Fatal(e)
	}
	f.peer = peer
	f.grant.ExecutorPeer = peer
	f.grant.Version = WindowsBackgroundUpdateRelayGrantVersion
	return f, config
}
func TestPublicUpdateAuthorityNeverReadsPrivateIdentityAndChecksAfterWaits(t *testing.T) {
	for _, mode := range []string{"normal", "expiry", "revoked", "renew-during-check", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f, c := publicUpdateFixture(t)
			reads := map[string]int{}
			a, e := openWindowsUpdatePublicAuthority(c, f.layout, func(context.Context) error {
				if f.onCheck != nil {
					f.onCheck()
				}
				return nil
			}, func(path string, _ bool, _ int64) ([]byte, error) {
				reads[path]++
				if path == f.current.config.PrivateKeyFile || strings.Contains(path, "agent-key") {
					t.Fatal("service read enrollment key")
				}
				return os.ReadFile(path)
			}, func(m Material) (WindowsUpdateRelayGrant, error) {
				if m.certificate.PrivateKey != nil || m.loaded || m.tlsConfig != nil {
					t.Fatal("service constructed private TLS material")
				}
				return f.grant, nil
			}, func() time.Time { return f.now })
			if e != nil {
				t.Fatal(e)
			}
			if reads[f.current.config.CertificateFile] == 0 || reads[f.current.config.RenewalManifestFile] == 0 {
				t.Fatal("public identity not read")
			}
			switch mode {
			case "expiry":
				f.onCheck = func() { f.now = time.Unix(f.grant.ExpiresAt, 0) }
			case "revoked":
				f.onCheck = func() { f.grant.Enabled = false }
			case "renew-during-check":
				f.onCheck = func() { f.material.write(t, f.material.renewed) }
			case "rollback":
				f.material.write(t, f.material.renewed)
				if e = a.WithCurrent(context.Background(), c.Consent.Binding, func(job.Current) error { return nil }); e != nil {
					t.Fatal(e)
				}
				f.material.write(t, f.material.initial)
			}
			called := false
			e = a.WithCurrent(context.Background(), c.Consent.Binding, func(job.Current) error { called = true; return nil })
			if mode == "normal" {
				if e != nil || !called {
					t.Fatal(e)
				}
			} else if e == nil || called {
				t.Fatal("stale authority reached native edge", mode)
			}
		})
	}
}
func TestBackgroundRegistrationSignatureCannotPromoteLegacy(t *testing.T) {
	f, c := publicUpdateFixture(t)
	_ = f
	bad := c
	bad.Version = windowsupdateipc.CoordinatedConfigVersion
	if bad.Validate() == nil {
		t.Fatal("legacy config adopted background")
	}
	bad = c
	bad.Consent.Version = job.CoordinatedConsentVersion
	bad.Consent.BackgroundAcknowledged = false
	if bad.Validate() == nil {
		t.Fatal("service adopted legacy")
	}
}
