package windowsmanagedmsi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	prepared "localrmm/internal/windowssoftwarejob"
	"strings"
	"testing"
)

func TestScheduledMSICompatibilityAndSignedIPCBound(t *testing.T) {
	f := fixture(t)
	defer f.x.Close()
	for _, version := range []string{Version, ReusableVersion, ScheduledVersion} {
		p := f.p
		p.Version = version
		if ReusableWire(version) {
			p.JobSequence = 1
			p.PublisherStatus = "unverified"
			p.PublisherEvidenceDigest = Digest([]byte("review"))
		}
		raw, e := SignPermit(p, f.manager)
		if e != nil {
			t.Fatal(e)
		}
		if version != ScheduledVersion {
			if bytes.Contains(raw, []byte("schedule")) {
				t.Fatal("legacy bytes promoted")
			}
			p.ScheduleDigest = Digest([]byte("schedule"))
			p.ScheduleStartAt = p.IssuedAt
			p.ScheduleEndAt = p.IssuedAt + 120
			if p.Validate() == nil {
				t.Fatal("old permit accepted scheduling")
			}
			continue
		}
		p.Kind = "readiness"
		p.Sequence = 2
		p.ExpiresAt = p.IssuedAt + 60
		p.MaintenanceUntil = p.IssuedAt + 600
		p.PackageReviewAccepted = true
		p.TermsAccepted = true
		p.Package.Name = strings.Repeat("<", 120)
		p.Package.ReviewReference = strings.Repeat("&", 160)
		p.SynchronousReviewDigest = SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest)
		p.ScheduleDigest = Digest([]byte("schedule"))
		p.ScheduleStartAt = p.IssuedAt
		p.ScheduleEndAt = p.MaintenanceUntil
		for _, kind := range []string{"readiness", "install"} {
			p.Kind = kind
			if kind == "install" {
				p.ReadinessDigest = Digest([]byte("readiness"))
			}
			raw, e = SignPermit(p, f.manager)
			if e != nil || len(raw) > 8192 {
				t.Fatal("IPC envelope bound", len(raw), e)
			}
			var signed signedPermit
			if json.Unmarshal(raw, &signed) != nil {
				t.Fatal("decode")
			}
			signed.Permit.Version = ReusableVersion
			signed.Permit.ScheduleDigest = ""
			signed.Permit.ScheduleStartAt = 0
			signed.Permit.ScheduleEndAt = 0
			changed, _ := json.Marshal(signed)
			if _, e = VerifyPermit(changed, f.manager.Public().(ed25519.PublicKey)); e == nil {
				t.Fatal("v4 signature downgraded")
			}
		}
	}
}
func TestScheduledMSIPhysicalFactsComparator(t *testing.T) {
	a := Readiness{Selection: fixture(t).p.Package, CapturedAt: 1800000000, PackageVerified: Yes, MachineAbsent: Yes, InstallerBusy: No, NativeAcceptance: Yes, PackageReviewAccepted: Yes, MaintenanceWindowEnd: 1800000600}
	b := a
	b.CapturedAt++
	b.MaintenanceWindowEnd += 120
	if !SameScheduledFacts(a, b) || prepared.SameFacts(a, b) {
		t.Fatal("maintenance comparison leaked into manual comparator")
	}
	variants := []Readiness{b, b, b, b, b, b}
	variants[0].Selection.Name = "different"
	variants[1].PackageVerified = Unknown
	variants[2].MachineAbsent = No
	variants[3].InstallerBusy = Yes
	variants[4].NativeAcceptance = No
	variants[5].PackageReviewAccepted = No
	for _, v := range variants {
		if SameScheduledFacts(a, v) {
			t.Fatal("physical fact dropped")
		}
	}
}
