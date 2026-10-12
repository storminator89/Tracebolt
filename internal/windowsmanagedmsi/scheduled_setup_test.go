package windowsmanagedmsi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	fence "localrmm/internal/windowsmutationfence"
	"strings"
	"testing"
)

func scheduledSetupFixture(t *testing.T) (SetupRegistration, fence.Roster) {
	t.Helper()
	d := func(s string) string { return Digest([]byte(s)) }
	pub := func(n byte) []byte {
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)).Public().(ed25519.PublicKey)
	}
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d("anchor"), ExecutorID: "executor_" + strings.Repeat("3", 32), KeyID: Digest(pub(1)), ExecutorKeyID: Digest(pub(2)), DeliveryGrantID: "grant_" + strings.Repeat("4", 32), InstallGrantID: "grant_" + strings.Repeat("5", 32)}
	g := Grant{Version: ScheduledGrantVersion, ScheduledEnabled: true, ScheduledAcknowledged: true, ReusableAcknowledged: true, MutationPlanDigest: d("plan"), PeerBindingDigest: d("peer binding"), Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: 1800003600}
	r := SetupRegistration{Version: ScheduledRegistrationVersion, Offer: SetupOffer{Version: ScheduledOfferVersion, ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest, ManagerOrigin: "https://manager.invalid", ManagerPublicKey: pub(1), ExpiresAt: g.ExpiresAt}, Grant: g, ExecutorPublicKey: pub(2)}
	roster := fence.Roster{Version: fence.BackgroundRosterVersion, Plan: fence.Plan{Version: fence.BackgroundPlanVersion, Identity: fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}, PlanDigest: g.MutationPlanDigest, MSIOfferDigest: d("offer"), WUAOfferDigest: d("wua offer"), MSIArtifactDigest: d("image"), WUAArtifactDigest: d("wua image")}, FenceID: d("fence"), MSI: MutationParticipant(g), WUA: fence.Participant{Domain: fence.CachedWUA, BindingDigest: g.PeerBindingDigest, GrantDigest: d("peer consent"), ManagerKeyDigest: Digest(pub(3)), ExecutorKeyDigest: Digest(pub(4))}}
	if r.Validate() != nil || !ValidMutationRoster(&roster, g) {
		t.Fatal("invalid scheduled setup fixture")
	}
	return r, roster
}

func TestScheduledSetupRequiresFreshExactProfileAndAcknowledgements(t *testing.T) {
	r, roster := scheduledSetupFixture(t)
	for name, mutate := range map[string]func(*SetupRegistration){
		"missing-enabled":      func(r *SetupRegistration) { r.Grant.ScheduledEnabled = false },
		"missing-schedule-ack": func(r *SetupRegistration) { r.Grant.ScheduledAcknowledged = false },
		"missing-reusable-ack": func(r *SetupRegistration) { r.Grant.ReusableAcknowledged = false },
		"old-grant":            func(r *SetupRegistration) { r.Grant.Version = ReusableGrantVersion },
		"old-offer":            func(r *SetupRegistration) { r.Offer.Version = ReusableOfferVersion },
		"old-registration":     func(r *SetupRegistration) { r.Version = ReusableRegistrationVersion },
	} {
		t.Run(name, func(t *testing.T) {
			c := r
			mutate(&c)
			raw, _ := json.Marshal(c)
			if c.Validate() == nil {
				t.Fatal("profile promoted")
			}
			if _, err := DecodeSetupRegistration(raw); err == nil {
				t.Fatal("decoder promoted profile")
			}
		})
	}
	if !r.Grant.Reusable() || !r.Grant.Scheduled() {
		t.Fatal("fresh eligibility missing")
	}
	changed := r.Grant
	changed.ExpiresAt++
	if ValidMutationRoster(&roster, changed) {
		t.Fatal("roster omitted full grant")
	}
	changed = r.Grant
	changed.ScheduledAcknowledged = false
	if ValidMutationRoster(&roster, changed) {
		t.Fatal("roster admitted missing acknowledgement")
	}
	roster.Version = fence.ReusableRosterVersion
	roster.Plan.Version = fence.ReusablePlanVersion
	if ValidMutationRoster(&roster, r.Grant) {
		t.Fatal("scheduled MSI paired with foreground update roster")
	}
}

func TestLegacyMSIGrantBytesAndDefaultOffRemainExact(t *testing.T) {
	r, _ := scheduledSetupFixture(t)
	for _, version := range []string{GrantVersion, CoordinatedGrantVersion, ReusableGrantVersion} {
		g := r.Grant
		g.Version = version
		g.ScheduledEnabled = false
		g.ScheduledAcknowledged = false
		g.ReusableAcknowledged = version == ReusableGrantVersion
		if version == GrantVersion {
			g.MutationPlanDigest = ""
			g.PeerBindingDigest = ""
		}
		old := struct {
			ReusableAcknowledged    bool    `json:"reusableAcknowledged,omitempty"`
			MutationPlanDigest      string  `json:"mutationPlanDigest,omitempty"`
			PeerBindingDigest       string  `json:"peerBindingDigest,omitempty"`
			Version                 string  `json:"version"`
			Binding                 Binding `json:"binding"`
			DeliveryEnabled         bool    `json:"deliveryEnabled"`
			InstallEnabled          bool    `json:"installEnabled"`
			DeliveryAcknowledged    bool    `json:"deliveryAcknowledged"`
			InstallAcknowledged     bool    `json:"installAcknowledged"`
			ServiceRiskAcknowledged bool    `json:"serviceRiskAcknowledged"`
			ExpiresAt               int64   `json:"expiresAt"`
		}{g.ReusableAcknowledged, g.MutationPlanDigest, g.PeerBindingDigest, g.Version, g.Binding, g.DeliveryEnabled, g.InstallEnabled, g.DeliveryAcknowledged, g.InstallAcknowledged, g.ServiceRiskAcknowledged, g.ExpiresAt}
		want, _ := json.Marshal(old)
		got, _ := json.Marshal(g)
		if g.Validate() != nil || g.Scheduled() || !bytes.Equal(want, got) {
			t.Fatal("legacy shape changed", version)
		}
		g.ScheduledAcknowledged = true
		if g.Validate() == nil {
			t.Fatal("old profile gained scheduling", version)
		}
	}
}
