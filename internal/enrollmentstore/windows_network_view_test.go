package enrollmentstore

import (
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsvolumes"
	"testing"
	"time"
)

func TestWindowsNetworkIndependentExpiryAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-25 * time.Hour)
	young := now.Add(-time.Minute)
	seq := uint64(1)
	base := WindowsInventoryView{ServerNow: now, Status: "fresh", Sequence: &seq, ReceivedAt: &young, Snapshot: &windowsmanaged.Snapshot{CollectedAt: young}, Network: &windowsnetwork.Snapshot{CollectedAt: old}, Volumes: &windowsvolumes.Snapshot{CollectedAt: young}}
	v, e := base.RecheckAt(now)
	if e != nil || v.Network != nil || v.Volumes == nil {
		t.Fatal("expired metrics hid young volumes", e)
	}
	base.Network = &windowsnetwork.Snapshot{CollectedAt: young}
	base.Volumes = &windowsvolumes.Snapshot{CollectedAt: old}
	v, e = base.RecheckAt(now)
	if e != nil || v.Network == nil || v.Volumes != nil {
		t.Fatal("expired volumes hid young metrics", e)
	}
	base.Status = "revoked"
	v, e = base.RecheckAt(now)
	if e != nil || v.Network != nil || v.Volumes != nil || v.Snapshot != nil {
		t.Fatal("revoked private data retained", e)
	}
}
