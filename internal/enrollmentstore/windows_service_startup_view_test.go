package enrollmentstore

import (
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsvolumes"
	"testing"
	"time"
)

func TestWindowsServiceStartupIndependentExpiryAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-25 * time.Hour)
	young := now.Add(-time.Minute)
	seq := uint64(1)
	base := WindowsInventoryView{ServerNow: now, Status: "fresh", Sequence: &seq, ReceivedAt: &young, Snapshot: &windowsmanaged.Snapshot{CollectedAt: young}, ServiceStartup: &windowsmanaged.ServiceStartupSnapshot{CollectedAt: old}, Volumes: &windowsvolumes.Snapshot{CollectedAt: young}}
	v, e := base.RecheckAt(now)
	if e != nil || v.ServiceStartup != nil || v.Volumes == nil {
		t.Fatal("expired startup metadata hid young volumes", e)
	}
	base.ServiceStartup = &windowsmanaged.ServiceStartupSnapshot{CollectedAt: young}
	base.Volumes = &windowsvolumes.Snapshot{CollectedAt: old}
	v, e = base.RecheckAt(now)
	if e != nil || v.ServiceStartup == nil || v.Volumes != nil {
		t.Fatal("expired volumes hid young startup metadata", e)
	}
	base.Status = "revoked"
	v, e = base.RecheckAt(now)
	if e != nil || v.ServiceStartup != nil || v.Volumes != nil || v.Snapshot != nil {
		t.Fatal("revoked private data retained", e)
	}
}
