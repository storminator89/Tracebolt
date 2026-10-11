package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsresourcecontext"
	"strings"
	"testing"
	"time"
)

func resourceStoreFrame(t *testing.T, seq uint64, at time.Time, useful bool) []byte {
	t.Helper()
	var f lanstore.Frame
	if json.Unmarshal(windowsUpdatesStoreFrame(t, seq, at), &f) != nil {
		t.Fatal("fixture")
	}
	r := windowsresourcecontext.Request{Consent: windowsresourcecontext.Consent{GrantID: strings.Repeat("6", 32)}, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: at}
	s := windowsresourcecontext.Empty(r, windowsresourcecontext.ErrBudget.Error())
	if useful {
		bytes := "17179869184"
		s.InstalledMemory = windowsresourcecontext.InstalledMemory{Quality: "observed", Source: "GetPhysicallyInstalledSystemMemory", InstalledBytes: &bytes}
	}

	f.SchemaVersion = lanstore.FrameWindowsResourceContextVersion
	f.WindowsResourceContext = &s
	b, _ := json.Marshal(f)
	return b
}
func TestWindowsResourceRetentionExpiryOmissionAndReplacement(t *testing.T) {
	for _, change := range []string{"expiry", "omission", "replacement"} {
		t.Run(change, func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			for i := uint64(1); i <= 2; i++ {
				when := at.Add(time.Duration(i-1) * 30 * time.Second)
				if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), resourceStoreFrame(t, i, when, i == 1), when); e != nil {
					t.Fatal(e)
				}
			}
			now := at.Add(30 * time.Second)
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext == nil || view.RetainedContext.ResourceContext == nil || !view.RetainedContext.ResourceContext.CollectedAt.Equal(at) || view.ResourceContext.Memory.Reason != windowsresourcecontext.ErrBudget.Error() {
				t.Fatal("retention lost original source/failure", e)
			}
			if change == "expiry" {
				view, e = view.RecheckAt(at.Add(24 * time.Hour))
				if e != nil || view.RetainedContext != nil && view.RetainedContext.ResourceContext != nil || view.ResourceContext == nil {
					t.Fatal("expiry changed latest or retained old data", e)
				}
				return
			}
			var f lanstore.Frame
			now = now.Add(30 * time.Second)
			json.Unmarshal(resourceStoreFrame(t, 3, now, false), &f)
			if change == "omission" {
				f.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
				f.WindowsResourceContext = nil
			} else {
				f.WindowsResourceContext.GrantID = strings.Repeat("7", 32)
			}
			b, _ := json.Marshal(f)
			if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), b, now); e != nil {
				t.Fatal(e)
			}
			view, e = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext != nil && view.RetainedContext.ResourceContext != nil {
				t.Fatal("old grant kept private CPU/memory", e)
			}
		})
	}
}

func TestWindowsResourceRetentionRejectsAllUnknownAndAcceptsNoPagefiles(t *testing.T) {
	var f lanstore.Frame
	json.Unmarshal(resourceStoreFrame(t, 1, time.Unix(testNow+10, 0).UTC(), false), &f)
	if usefulResource(f.WindowsResourceContext) {
		t.Fatal("all unknown refreshed capture")
	}
	f.WindowsResourceContext.Processors = windowsresourcecontext.Processors{Quality: "partial", Reason: windowsresourcecontext.ErrPartial.Error(), Source: "Win32_Processor", Rows: []windowsresourcecontext.Processor{{Name: windowsresourcecontext.Field{Quality: "empty"}, Architecture: windowsresourcecontext.Field{Quality: "unavailable"}, Cores: windowsresourcecontext.CountField{Quality: "unavailable"}, LogicalProcessors: windowsresourcecontext.CountField{Quality: "unavailable"}}}}
	if windowsresourcecontext.Validate(*f.WindowsResourceContext) != nil || usefulResource(f.WindowsResourceContext) {
		t.Fatal("all unknown CPU rows refreshed capture")
	}
	zero := uint32(0)
	b := "0"
	f.WindowsResourceContext.Pagefiles = windowsresourcecontext.Pagefiles{Quality: "observed", Source: "EnumPageFilesW", Count: &zero, TotalBytes: &b, TotalInUseBytes: &b}
	if windowsresourcecontext.Validate(*f.WindowsResourceContext) != nil || !usefulResource(f.WindowsResourceContext) {
		t.Fatal("complete no-pagefile observation lost")
	}
}
