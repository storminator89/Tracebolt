package windowsmanagedmsiservice

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowsupdatejob"
	"strings"
	"testing"
)

func backgroundActivationFixture(t *testing.T) (windowsmanagedmsiipc.Config, Activation) {
	t.Helper()
	d := func(s string) string { return managed.Digest([]byte(s)) }
	id := func(p, s string) string { return p + strings.Repeat(s, 32) }
	key := func(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
	pub := func(n byte) []byte { return key(n).Public().(ed25519.PublicKey) }
	mb := managed.Binding{ManagerID: id("manager_", "1"), DeviceID: id("agent_", "2"), IncarnationDigest: d("anchor"), ExecutorID: id("executor_", "3"), ExecutorKeyID: managed.Digest(pub(2)), KeyID: managed.Digest(pub(1)), DeliveryGrantID: id("grant_", "4"), InstallGrantID: id("grant_", "5")}
	wb := job.Binding{ManagerID: mb.ManagerID, DeviceID: mb.DeviceID, IncarnationDigest: mb.IncarnationDigest, ExecutorID: id("executor_", "6"), ExecutorKeyID: managed.Digest(pub(4)), KeyID: managed.Digest(pub(3)), GrantID: id("grant_", "7")}
	mr, _ := json.Marshal(mb)
	wr, _ := json.Marshal(wb)
	g := managed.Grant{Version: managed.ReusableGrantVersion, MutationPlanDigest: d("plan"), PeerBindingDigest: managed.Digest(wr), Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ReusableAcknowledged: true, ExpiresAt: 1800003600}
	c := job.Consent{Version: job.BackgroundConsentVersion, BackgroundAcknowledged: true, MutationPlanDigest: d("plan"), PeerBindingDigest: managed.Digest(mr), Scope: job.Scope, Binding: wb, Enabled: true, Acknowledged: true, ExpiresAt: 1800003600}
	roster := fence.Roster{Version: fence.BackgroundRosterVersion, Plan: fence.Plan{Version: fence.BackgroundPlanVersion, Identity: fence.Identity{ManagerID: mb.ManagerID, DeviceID: mb.DeviceID, IncarnationDigest: mb.IncarnationDigest}, PlanDigest: d("plan"), MSIOfferDigest: d("msi offer"), WUAOfferDigest: d("wua offer"), MSIArtifactDigest: d("msi image"), WUAArtifactDigest: d("wua image")}, FenceID: d("fence"), MSI: managed.MutationParticipant(g), WUA: job.MutationParticipant(c)}
	config := windowsmanagedmsiipc.Config{Version: windowsmanagedmsiipc.ReusableConfigVersion, Mutation: &roster, Grant: g, ObserverConfigDigest: d("observer config"), SenderBinding: "sender", ManagerOrigin: "https://manager.invalid", ManagerPublicKey: pub(1), ExecutorPublicKey: pub(2), Executable: `C:\Program Files\Tracebolt\tracebolt-windows-managed-msi-service.exe`, ExecutableDigest: d("image"), ObserverReceipt: windowsservice.Receipt{Version: 1, InstallationID: "fixture", ServiceSID: "S-1-5-80-1-2-3-4-5", Complete: true}, ObserverProcessQueryAcknowledged: true}
	registration := job.SetupRegistration{Version: job.BackgroundRegistrationVersion, Offer: job.SetupOffer{Version: job.SetupOfferVersion, ManagerID: wb.ManagerID, DeviceID: wb.DeviceID, IncarnationDigest: wb.IncarnationDigest, ManagerOrigin: config.ManagerOrigin, ManagerPublicKey: pub(3), ExpiresAt: c.ExpiresAt}, Consent: c, ExecutorPublicKey: pub(4)}
	manager, e := job.SignBackgroundActivation(registration, key(3))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(config)
	a := Activation{Version: BackgroundActivationVersion, ConfigDigest: managed.Digest(raw), Acknowledged: true, Background: &BackgroundRegistrationProof{Registration: registration, Manager: manager}}
	if config.Validate() != nil || a.Validate(config) != nil {
		t.Fatal("bad fresh proof fixture")
	}
	return config, a
}
func TestBackgroundMSIActivationRequiresExactPairedManagerProof(t *testing.T) {
	c, a := backgroundActivationFixture(t)
	for _, kind := range []string{"missing", "legacy-version", "wrong-signature", "wrong-registration"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(a)
			var b Activation
			json.Unmarshal(raw, &b)
			switch kind {
			case "missing":
				b.Background = nil
			case "legacy-version":
				b.Version = managed.Version
			case "wrong-signature":
				b.Background.Manager.Signature[0] ^= 1
			case "wrong-registration":
				b.Background.Registration.Consent.ExpiresAt++
			}
			if b.Validate(c) == nil {
				t.Fatal("missing/unrecognized registration activated background pairing")
			}
		})
	}
}
func TestBackgroundMSIActivationPreservesLegacyBytesAndDenial(t *testing.T) {
	c, a := backgroundActivationFixture(t)
	old := Activation{Version: managed.Version, ConfigDigest: a.ConfigDigest, Acknowledged: true}
	raw, _ := json.Marshal(old)
	want, _ := json.Marshal(struct {
		Version      string `json:"version"`
		ConfigDigest string `json:"configDigest"`
		Acknowledged bool   `json:"acknowledged"`
	}{managed.Version, a.ConfigDigest, true})
	if !bytes.Equal(raw, want) {
		t.Fatal("legacy activation bytes changed")
	}
	roster := *c.Mutation
	roster.Version = fence.ReusableRosterVersion
	roster.Plan.Version = fence.ReusablePlanVersion
	c.Mutation = &roster
	raw, _ = json.Marshal(c)
	old.ConfigDigest = managed.Digest(raw)
	if old.Validate(c) != nil {
		t.Fatal("legacy activation denied")
	}
	a.ConfigDigest = old.ConfigDigest
	if a.Validate(c) == nil {
		t.Fatal("legacy roster adopted new proof")
	}
}
