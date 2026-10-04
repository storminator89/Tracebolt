package analysis

import (
	"encoding/json"
	"testing"
)

func TestPacketRejectsOperationalCaseOrMixedEvidenceBeforeCopy(t *testing.T) {
	for _, profile := range []string{"managed-operations-v1", "unknown-profile"} {
		c, available := sampleCase()
		c.CollectionProfile = profile
		c.Title = "private operational label"
		packet, e := BuildPacket(c, available)
		if e == nil || packet.Case.Title != "" {
			t.Fatal("operational case copied")
		}
	}
	c, available := sampleCase()
	available[0].CollectionProfile = "managed-operations-v1"
	packet, e := BuildPacket(c, available)
	if e == nil || len(packet.Evidence) != 0 {
		t.Fatal("managed evidence copied")
	}
	c, available = sampleCase()
	c.Evidence[0].CollectionProfile = "managed-operations-v1"
	c.EvidenceIDs = nil
	if _, e = BuildPacket(c, available); e == nil {
		t.Fatal("mixed case provenance ignored")
	}
	c, available = sampleCase()
	c.CollectionProfile = "managed-operations-v1"
	raw, _ := json.Marshal(c)
	c.CollectionProfile = ""
	json.Unmarshal(raw, &c)
	if _, e = BuildPacket(c, available); e == nil {
		t.Fatal("stored provenance disappeared")
	}
}
