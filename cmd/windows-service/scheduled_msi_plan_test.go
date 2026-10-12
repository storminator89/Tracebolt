package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/lanclient"
	managed "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
	"runtime"
	"strings"
	"testing"
)

func scheduledMSIPairedPlanFixture(t *testing.T, scheduledWUA bool) coordinatedMutationPlan {
	t.Helper()
	d := func(s string) string { return managed.Digest([]byte(s)) }
	pub := func(n byte) []byte {
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)).Public().(ed25519.PublicKey)
	}
	o := job.SetupOffer{Version: job.SetupOfferVersion, ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d("anchor"), ManagerOrigin: "https://manager.invalid", ManagerPublicKey: pub(1), ExpiresAt: 1800000300}
	i := lanclient.WindowsUpdateSetupIdentity{ManagerID: o.ManagerID, DeviceID: o.DeviceID, IncarnationDigest: o.IncarnationDigest, ManagerOrigin: o.ManagerOrigin, SenderBinding: "sender", ConfigDigest: d("config"), LeafDigest: d("leaf"), LeafPublicKeyDigest: d("TLS key"), LeafNotBefore: 1799999940, LeafNotAfter: 1800000600}
	r := windowsservice.Receipt{Version: 1, InstallationID: "fixture", Complete: true, ServiceSID: "S-1-5-80-1-2-3-4-5", Layout: windowsservice.Layout{ProgramFiles: `C:\Program Files`, StateRoot: `C:\ProgramData\Tracebolt\windows-agent`}}
	artifact := windowspackage.Manifest{SchemaVersion: windowspackage.ManifestSchema, Version: "v0.1.0-fixture", SourceCommit: strings.Repeat("a", 40), Architecture: runtime.GOARCH, SHA256: strings.Repeat("b", 64)}
	create := windowsupdatesetup.NewBackgroundPlan
	if scheduledWUA {
		create = windowsupdatesetup.NewScheduledBackgroundPlan
	}
	w, e := create(o, artifact, i, r)
	if e != nil {
		t.Fatal(e)
	}
	m := managedMSIPlan{Version: "tracebolt.windows-managed-msi-endpoint-plan.v4", ScheduledDisclosure: managed.ScheduledDisclosure, Offer: managed.SetupOffer{Version: managed.ScheduledOfferVersion, ManagerID: o.ManagerID, DeviceID: o.DeviceID, IncarnationDigest: o.IncarnationDigest, ManagerOrigin: o.ManagerOrigin, ManagerPublicKey: pub(2), ExpiresAt: o.ExpiresAt}, Artifact: artifact, Identity: lanclient.WindowsManagedMSISetupIdentity(i), Observer: r, DeliveryDisclosure: managed.ReusableDisclosure, InstallDisclosure: managed.ReusableDisclosure, ServiceDisclosure: managed.ServiceDisclosure, RelayDisclosure: lanclient.WindowsManagedMSIRelayDisclosure}
	p := coordinatedMutationPlan{Version: scheduledMSIMutationVersion, MSI: m, WUA: w, Disclosure: windowsupdatesetup.BackgroundDisclosure + " " + managed.ReusableDisclosure + " " + managed.ScheduledDisclosure}
	if scheduledWUA {
		p.Version = scheduledMSIAndWUAMutationVersion
		p.Disclosure = windowsupdatesetup.ScheduledBackgroundDisclosure + " " + job.BackgroundScheduleDisclosure + " " + managed.ReusableDisclosure + " " + managed.ScheduledDisclosure
	}
	return p
}

func TestScheduledMSIPairedPlansRetainIndependentWUAScheduling(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("paired MSI profile is x64 only")
	}
	for _, scheduledWUA := range []bool{false, true} {
		p := scheduledMSIPairedPlanFixture(t, scheduledWUA)
		if p.Validate() != nil || p.FencePlan().Validate() != nil || p.FencePlan().Version != fence.BackgroundPlanVersion {
			t.Fatal("fresh paired profile rejected")
		}
		for _, mutate := range []func(*coordinatedMutationPlan){func(p *coordinatedMutationPlan) { p.MSI.Offer.Version = managed.ReusableOfferVersion }, func(p *coordinatedMutationPlan) { p.MSI.ScheduledDisclosure = "" }, func(p *coordinatedMutationPlan) { p.Version = scheduledBackgroundMutationVersion }, func(p *coordinatedMutationPlan) { p.Disclosure = managed.ReusableDisclosure }} {
			c := p
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("missing exact fresh profile accepted")
			}
			if c.Digest() == p.Digest() {
				t.Fatal("changed profile omitted from digest")
			}
		}
		c := p
		c.MSI.Offer.ExpiresAt--
		if c.FencePlan().MSIOfferDigest == p.FencePlan().MSIOfferDigest {
			t.Fatal("full MSI offer not bound")
		}
	}
}

func TestLegacyMSIEndpointPlanOmitsScheduledDisclosure(t *testing.T) {
	p := managedMSIPlan{Version: "tracebolt.windows-managed-msi-endpoint-plan.v3", Offer: managed.SetupOffer{Version: managed.ReusableOfferVersion}}
	raw, _ := json.Marshal(p)
	if bytes.Contains(raw, []byte("scheduled")) {
		t.Fatal("old endpoint plan bytes changed")
	}
	want := managed.Digest(append([]byte("Tracebolt reusable MSI endpoint setup v3\x00"), raw...))
	if p.Digest() != want {
		t.Fatal("old endpoint setup digest changed")
	}
}
