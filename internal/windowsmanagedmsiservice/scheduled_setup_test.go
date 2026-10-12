package windowsmanagedmsiservice

import (
	"encoding/json"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"testing"
)

func TestScheduledMSIServiceConfigAndActivationPinFullFreshGrant(t *testing.T) {
	c, a := backgroundActivationFixture(t)
	c.Grant.Version = managed.ScheduledGrantVersion
	c.Grant.ScheduledEnabled = true
	c.Grant.ScheduledAcknowledged = true
	c.Version = windowsmanagedmsiipc.ScheduledConfigVersion
	roster := *c.Mutation
	roster.MSI = managed.MutationParticipant(c.Grant)
	c.Mutation = &roster
	raw, _ := json.Marshal(c)
	a.ConfigDigest = managed.Digest(raw)
	if c.Validate() != nil || a.Validate(c) != nil || !validPairedSetupVersion(ScheduledSetupVersion, c.Grant) {
		t.Fatal("fresh scheduled service profile rejected")
	}
	for _, version := range []string{SetupVersion, CoordinatedSetupVersion, ReusableSetupVersion} {
		if validPairedSetupVersion(version, c.Grant) {
			t.Fatal("earlier receipt adopted scheduled grant", version)
		}
	}
	old := c
	old.Version = windowsmanagedmsiipc.ReusableConfigVersion
	if old.Validate() == nil {
		t.Fatal("old config adopted scheduled grant")
	}
	c.Grant.ScheduledAcknowledged = false
	if c.Validate() == nil || a.Validate(c) == nil {
		t.Fatal("lost scheduling authority accepted")
	}
}
