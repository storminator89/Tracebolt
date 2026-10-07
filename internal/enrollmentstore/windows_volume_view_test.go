package enrollmentstore

import (
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsvolumes"
	"testing"
	"time"
)

func TestWindowsVolumeViewIndependentExpiryAndRevocation(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	seq := uint64(1)
	received := at
	view := WindowsInventoryView{ServerNow: at, Status: "fresh", Sequence: &seq, ReceivedAt: &received, Snapshot: &windowsmanaged.Snapshot{CollectedAt: at}, Events: &windowseventhealth.Snapshot{CollectedAt: at.Add(-24 * time.Hour)}, Volumes: &windowsvolumes.Snapshot{CollectedAt: at}}
	out, err := view.RecheckAt(at)
	if err != nil || out.Events != nil || out.Volumes == nil {
		t.Fatal("older events hid younger volume snapshot", err)
	}
	view.Events.CollectedAt = at
	view.Volumes.CollectedAt = at.Add(-24 * time.Hour)
	out, err = view.RecheckAt(at)
	if err != nil || out.Events == nil || out.Volumes != nil {
		t.Fatal("older volume hid younger events", err)
	}
	view.Volumes.CollectedAt = at
	view.certificateNotAfter = at.Add(time.Second).Unix()
	out, err = view.RecheckAt(at.Add(time.Second))
	if err != nil || out.Volumes != nil || out.Events != nil || out.Snapshot != nil || out.Status != "revoked" {
		t.Fatal("revocation retained capabilities", err)
	}
}
