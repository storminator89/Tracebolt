package enrollmentstore

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsstorage"
	"strings"
	"testing"
	"time"
)

func storageStoreFrame(t *testing.T, seq uint64, at time.Time, useful bool) []byte {
	t.Helper()
	var f lanstore.Frame
	if json.Unmarshal(windowsUpdatesStoreFrame(t, seq, at), &f) != nil {
		t.Fatal("fixture")
	}
	r := windowsstorage.Request{Consent: windowsstorage.Consent{GrantID: strings.Repeat("6", 32)}, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: at}
	s := windowsstorage.Empty(r, windowsstorage.ErrBudget.Error())
	if useful {
		name := "private-disk"
		s.Disks = windowsstorage.Disks{Quality: "partial", Reason: windowsstorage.ErrPartial.Error(), Rows: []windowsstorage.Disk{{Index: 0, DeviceID: windowsstorage.Field{Quality: "unavailable"}, FriendlyName: windowsstorage.Field{Value: &name, Quality: "observed"}, OperationalStatus: []uint16{}}}, ObservedCount: 1, CountExact: true, Complete: true}
	}

	f.SchemaVersion = lanstore.FrameWindowsStorageContextVersion
	f.WindowsStorageContext = &s
	b, _ := json.Marshal(f)
	return b
}
func TestWindowsStorageRetentionExpiryOmissionAndReplacement(t *testing.T) {
	for _, change := range []string{"expiry", "omission", "replacement"} {
		t.Run(change, func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			for i := uint64(1); i <= 2; i++ {
				when := at.Add(time.Duration(i-1) * 30 * time.Second)
				if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), storageStoreFrame(t, i, when, i == 1), when); e != nil {
					t.Fatal(e)
				}
			}
			now := at.Add(30 * time.Second)
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext == nil || view.RetainedContext.StorageContext == nil || !view.RetainedContext.StorageContext.CollectedAt.Equal(at) || view.StorageContext.Disks.Reason != windowsstorage.ErrBudget.Error() {
				t.Fatal("retention lost original source/failure", e)
			}
			if change == "expiry" {
				view, e = view.RecheckAt(at.Add(24 * time.Hour))
				if e != nil || view.RetainedContext != nil && view.RetainedContext.StorageContext != nil || view.StorageContext == nil {
					t.Fatal("expiry changed latest or retained old data", e)
				}
				return
			}
			var f lanstore.Frame
			now = now.Add(30 * time.Second)
			json.Unmarshal(storageStoreFrame(t, 3, now, false), &f)
			if change == "omission" {
				f.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
				f.WindowsStorageContext = nil
			} else {
				f.WindowsStorageContext.GrantID = strings.Repeat("7", 32)
			}
			b, _ := json.Marshal(f)
			if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), b, now); e != nil {
				t.Fatal(e)
			}
			view, e = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext != nil && view.RetainedContext.StorageContext != nil {
				t.Fatal("old grant kept private serial", e)
			}
		})
	}
}

func TestWindowsStorageAllUnknownDoesNotReplaceUsefulCapture(t *testing.T) {
	for _, code := range []uint16{0, 65535} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), storageStoreFrame(t, 1, at, true), at); e != nil {
				t.Fatal(e)
			}
			now := at.Add(30 * time.Second)
			var f lanstore.Frame
			json.Unmarshal(storageStoreFrame(t, 2, now, false), &f)
			f.WindowsStorageContext.Disks = windowsstorage.Disks{Quality: "partial", Reason: windowsstorage.ErrPartial.Error(), Rows: []windowsstorage.Disk{{Index: 0, DeviceID: windowsstorage.Field{Quality: "unavailable"}, FriendlyName: windowsstorage.Field{Quality: "unavailable"}, OperationalStatus: []uint16{}}}, ObservedCount: 1, CountExact: true, Complete: true}
			row := &f.WindowsStorageContext.Disks.Rows[0]
			health := uint16(5)
			if code == 65535 {
				health = code
			}
			row.HealthStatus = &health
			row.BusType = &code
			row.MediaType = &code
			row.OperationalStatus = []uint16{code}

			raw, _ := json.Marshal(f)
			if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, now); e != nil {
				t.Fatal(e)
			}
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.StorageContext.Disks.Quality != "partial" || view.RetainedContext == nil || view.RetainedContext.StorageContext == nil || !view.RetainedContext.StorageContext.CollectedAt.Equal(at) {
				t.Fatal("unknown result refreshed useful context", e)
			}
		})
	}
}

func TestWindowsStorageUsefulRequiresRecognizedValues(t *testing.T) {
	var f lanstore.Frame
	json.Unmarshal(storageStoreFrame(t, 1, time.Unix(testNow+10, 0).UTC(), false), &f)
	for _, tc := range []struct {
		field string
		code  uint16
		want  bool
	}{{"health", 0, true}, {"health", 1, true}, {"health", 2, true}, {"health", 5, false}, {"health", 65535, false}, {"bus", 0, false}, {"bus", 1, true}, {"bus", 13, true}, {"bus", 14, false}, {"bus", 15, true}, {"bus", 17, true}, {"bus", 65535, false}, {"media", 0, false}, {"media", 3, true}, {"media", 4, true}, {"media", 5, true}, {"media", 65535, false}, {"operation", 0, false}, {"operation", 1, false}, {"operation", 2, true}, {"operation", 18, true}, {"operation", 65535, false}} {
		s := *f.WindowsStorageContext
		s.Disks = windowsstorage.Disks{Quality: "partial", Reason: windowsstorage.ErrPartial.Error(), Rows: []windowsstorage.Disk{{Index: 0, DeviceID: windowsstorage.Field{Quality: "unavailable"}, FriendlyName: windowsstorage.Field{Quality: "unavailable"}, OperationalStatus: []uint16{}}}, ObservedCount: 1, CountExact: true, Complete: true}
		r := &s.Disks.Rows[0]
		switch tc.field {
		case "health":
			r.HealthStatus = &tc.code
		case "bus":
			r.BusType = &tc.code
		case "media":
			r.MediaType = &tc.code
		case "operation":
			r.OperationalStatus = []uint16{tc.code}
		}
		if windowsstorage.Validate(s) != nil || usefulStorage(&s) != tc.want {
			t.Fatal("wrong enum usefulness", tc)
		}
	}
	s := *f.WindowsStorageContext
	s.Disks = windowsstorage.Disks{Quality: "observed", Rows: []windowsstorage.Disk{}, CountExact: true, Complete: true}
	if !usefulStorage(&s) {
		t.Fatal("real empty enumeration lost")
	}
}
