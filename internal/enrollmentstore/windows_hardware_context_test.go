package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowshardware"
	"strings"
	"testing"
	"time"
)

func hardwareStoreFrame(t *testing.T, seq uint64, at time.Time, useful bool) []byte {
	t.Helper()
	var f lanstore.Frame
	if json.Unmarshal(windowsUpdatesStoreFrame(t, seq, at), &f) != nil {
		t.Fatal("fixture")
	}
	r := windowshardware.Request{Consent: windowshardware.Consent{GrantID: strings.Repeat("6", 32)}, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: at}
	s := windowshardware.Empty(r, windowshardware.ErrBudget.Error())
	if useful {
		serial := "private-chassis"
		s.Chassis = windowshardware.Chassis{Quality: "observed", Source: "Win32_SystemEnclosure", SerialNumber: windowshardware.Field{Value: &serial, Quality: "observed"}}
	}
	f.SchemaVersion = lanstore.FrameWindowsHardwareContextVersion
	f.WindowsHardwareContext = &s
	b, _ := json.Marshal(f)
	return b
}
func TestWindowsHardwareRetentionExpiryOmissionAndReplacement(t *testing.T) {
	for _, change := range []string{"expiry", "omission", "replacement"} {
		t.Run(change, func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			for i := uint64(1); i <= 2; i++ {
				when := at.Add(time.Duration(i-1) * 30 * time.Second)
				if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), hardwareStoreFrame(t, i, when, i == 1), when); e != nil {
					t.Fatal(e)
				}
			}
			now := at.Add(30 * time.Second)
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext == nil || view.RetainedContext.HardwareContext == nil || !view.RetainedContext.HardwareContext.CollectedAt.Equal(at) || view.HardwareContext.Power.Reason != windowshardware.ErrBudget.Error() {
				t.Fatal("retention lost original source/failure", e)
			}
			if change == "expiry" {
				view, e = view.RecheckAt(at.Add(24 * time.Hour))
				if e != nil || view.RetainedContext != nil && view.RetainedContext.HardwareContext != nil || view.HardwareContext == nil {
					t.Fatal("expiry changed latest or retained old data", e)
				}
				return
			}
			var f lanstore.Frame
			now = now.Add(30 * time.Second)
			json.Unmarshal(hardwareStoreFrame(t, 3, now, false), &f)
			if change == "omission" {
				f.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
				f.WindowsHardwareContext = nil
			} else {
				f.WindowsHardwareContext.GrantID = strings.Repeat("7", 32)
			}
			b, _ := json.Marshal(f)
			if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), b, now); e != nil {
				t.Fatal(e)
			}
			view, e = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext != nil && view.RetainedContext.HardwareContext != nil {
				t.Fatal("old grant kept private serial", e)
			}
		})
	}
}

func TestWindowsHardwareAllUnknownPartialPreservesUsefulRetention(t *testing.T) {
	_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), hardwareStoreFrame(t, 1, at, true), at); e != nil {
		t.Fatal(e)
	}
	now := at.Add(30 * time.Second)
	var f lanstore.Frame
	if e := json.Unmarshal(hardwareStoreFrame(t, 2, now, false), &f); e != nil {
		t.Fatal(e)
	}
	// The production powerStatus(255,255,255,0xffffffff) yields exactly this
	// valid partial Power, with every value still unknown and no measurements.
	f.WindowsHardwareContext.Power = windowshardware.EmptyPower(windowshardware.ErrPartial.Error())
	f.WindowsHardwareContext.Power.Quality = "partial"
	if e := windowshardware.Validate(*f.WindowsHardwareContext); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, now); e != nil {
		t.Fatal(e)
	}
	view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
	if e != nil {
		t.Fatal(e)
	}
	if view.HardwareContext.Power.Quality != "partial" {
		t.Fatal("current failure lost")
	}
	if view.RetainedContext == nil || view.RetainedContext.HardwareContext == nil {
		t.Fatal("all-unknown partial power discarded the previous useful chassis capture")
	}
	if !view.RetainedContext.HardwareContext.CollectedAt.Equal(at) {
		t.Fatal("original age changed")
	}
}

func TestWindowsHardwareRetentionNeedsRealValue(t *testing.T) {
	var f lanstore.Frame
	if json.Unmarshal(hardwareStoreFrame(t, 1, time.Unix(testNow+10, 0).UTC(), false), &f) != nil {
		t.Fatal("fixture")
	}
	s := *f.WindowsHardwareContext
	s.Power = windowshardware.EmptyPower(windowshardware.ErrPartial.Error())
	s.Power.Quality = "partial"
	if windowshardware.Validate(s) != nil || usefulHardware(&s) {
		t.Fatal("all unknown became useful")
	}
	s.System.Quality = "partial"
	s.System.Reason = windowshardware.ErrPartial.Error()
	if windowshardware.Validate(s) != nil || usefulHardware(&s) {
		t.Fatal("all unknown text became useful")
	}
	for _, state := range []string{"present", "absent"} {
		known := s
		known.Power.BatteryPresence = state
		if windowshardware.Validate(known) != nil || !usefulHardware(&known) {
			t.Fatal("known battery state lost", state)
		}
	}
	for _, state := range []string{"online", "offline"} {
		known := s
		known.Power.ACLineStatus = state
		if windowshardware.Validate(known) != nil || !usefulHardware(&known) {
			t.Fatal("known AC state lost", state)
		}
	}
	value := "known model"
	s.System.Model = windowshardware.Field{Value: &value, Quality: "observed"}
	if windowshardware.Validate(s) != nil || !usefulHardware(&s) {
		t.Fatal("known partial text lost")
	}
}
