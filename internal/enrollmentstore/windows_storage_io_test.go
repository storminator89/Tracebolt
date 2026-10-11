package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsstorageio"
	"strings"
	"testing"
	"time"
)

func storageIOStoreFrame(t *testing.T, seq uint64, at time.Time, useful bool) []byte {
	t.Helper()
	var f lanstore.Frame
	if json.Unmarshal(windowsUpdatesStoreFrame(t, seq, at), &f) != nil {
		t.Fatal("fixture")
	}
	r := windowsstorageio.Request{Consent: windowsstorageio.Consent{GrantID: strings.Repeat("6", 32)}, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: at}
	s := windowsstorageio.Empty(r, windowsstorageio.ErrBudget.Error())
	if useful {
		start, end, interval := at, at.Add(time.Second), uint64(1000)
		value := 0.25
		metric := windowsstorageio.Metric{Quality: "observed", Value: &value}
		s.PerfDisk = windowsstorageio.PerfDisk{Quality: "observed", Source: windowsstorageio.Source, SampleStartedAt: &start, SampleEndedAt: &end, IntervalMilliseconds: &interval, ReadBytesPerSecond: metric, WriteBytesPerSecond: metric, ReadOperationsPerSecond: metric, WriteOperationsPerSecond: metric, ReadLatencySeconds: metric, WriteLatencySeconds: metric, AverageQueueLength: metric, CurrentQueueLength: metric}
		f.Observation.GeneratedAt = end
	}

	f.SchemaVersion = lanstore.FrameWindowsStorageIOVersion
	f.WindowsStorageIO = &s
	b, _ := json.Marshal(f)
	return b
}
func TestWindowsStorageIORetentionExpiryOmissionAndReplacement(t *testing.T) {
	for _, change := range []string{"expiry", "omission", "replacement"} {
		t.Run(change, func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			for i := uint64(1); i <= 2; i++ {
				when := at.Add(time.Duration(i-1) * 30 * time.Second)
				if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), storageIOStoreFrame(t, i, when, i == 1), when); e != nil {
					t.Fatal(e)
				}
			}
			now := at.Add(30 * time.Second)
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext == nil || view.RetainedContext.StorageIO == nil || !view.RetainedContext.StorageIO.CollectedAt.Equal(at) || view.StorageIO.PerfDisk.Reason != windowsstorageio.ErrBudget.Error() {
				t.Fatal("retention lost original source/failure", e)
			}
			if change == "expiry" {
				view, e = view.RecheckAt(at.Add(24 * time.Hour))
				if e != nil || view.RetainedContext != nil && view.RetainedContext.StorageIO != nil || view.StorageIO == nil {
					t.Fatal("expiry changed latest or retained old data", e)
				}
				return
			}
			var f lanstore.Frame
			now = now.Add(30 * time.Second)
			json.Unmarshal(storageIOStoreFrame(t, 3, now, false), &f)
			if change == "omission" {
				f.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
				f.WindowsStorageIO = nil
			} else {
				f.WindowsStorageIO.GrantID = strings.Repeat("7", 32)
			}
			b, _ := json.Marshal(f)
			if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), b, now); e != nil {
				t.Fatal(e)
			}
			view, e = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext != nil && view.RetainedContext.StorageIO != nil {
				t.Fatal("old grant kept private CPU/memory", e)
			}
		})
	}
}

func TestWindowsStorageIORetentionRejectsAllUnknownAndAcceptsIdleRates(t *testing.T) {
	var f lanstore.Frame
	json.Unmarshal(storageIOStoreFrame(t, 1, time.Unix(testNow+10, 0).UTC(), false), &f)
	if usefulStorageIO(f.WindowsStorageIO) {
		t.Fatal("unknown refreshed capture")
	}
	json.Unmarshal(storageIOStoreFrame(t, 1, time.Unix(testNow+10, 0).UTC(), true), &f)
	p := &f.WindowsStorageIO.PerfDisk
	zero := 0.0
	p.ReadOperationsPerSecond.Value = &zero
	p.WriteOperationsPerSecond.Value = &zero
	p.ReadLatencySeconds = windowsstorageio.EmptyMetric(windowsstorageio.ErrIdle.Error())
	p.WriteLatencySeconds = p.ReadLatencySeconds
	p.Quality = "partial"
	p.Reason = windowsstorageio.ErrPartial.Error()
	if windowsstorageio.Validate(*f.WindowsStorageIO) != nil || !usefulStorageIO(f.WindowsStorageIO) {
		t.Fatal("idle rate lost")
	}
}
