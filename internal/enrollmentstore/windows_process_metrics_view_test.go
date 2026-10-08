package enrollmentstore

import (
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"testing"
	"time"
)

func TestWindowsProcessMetricsIndependentExpiryAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-25 * time.Hour)
	young := now.Add(-time.Minute)
	seq := uint64(1)
	base := WindowsInventoryView{ServerNow: now, Status: "fresh", Sequence: &seq, ReceivedAt: &young, Snapshot: &windowsmanaged.Snapshot{CollectedAt: young}, ProcessMetrics: &windowsprocessmetrics.Snapshot{CollectedAt: old}, Volumes: &windowsvolumes.Snapshot{CollectedAt: young}}
	v, e := base.RecheckAt(now)
	if e != nil || v.ProcessMetrics != nil || v.Volumes == nil {
		t.Fatal("expired metrics hid young volumes", e)
	}
	base.ProcessMetrics = &windowsprocessmetrics.Snapshot{CollectedAt: young}
	base.Volumes = &windowsvolumes.Snapshot{CollectedAt: old}
	v, e = base.RecheckAt(now)
	if e != nil || v.ProcessMetrics == nil || v.Volumes != nil {
		t.Fatal("expired volumes hid young metrics", e)
	}
	base.Status = "revoked"
	v, e = base.RecheckAt(now)
	if e != nil || v.ProcessMetrics != nil || v.Volumes != nil || v.Snapshot != nil {
		t.Fatal("revoked private data retained", e)
	}
}
