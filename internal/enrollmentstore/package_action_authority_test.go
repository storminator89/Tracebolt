package enrollmentstore

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

func TestNativePackageRenewalPolicyFailsClosed(t *testing.T) {
	legacy := enrollmentstate.Snapshot{}
	if err := packageRenewalSupported(legacy); err != nil {
		t.Fatal("legacy identity rejected", err)
	}
	for _, policy := range []string{enrollmentcrypto.RenewalPolicySameKey, "unknown-renewal-policy"} {
		snapshot := legacy
		snapshot.Claim.RenewalPolicy = policy
		if err := packageRenewalSupported(snapshot); !errors.Is(err, ErrPackageRenewalUnsupported) {
			t.Fatal("renewable identity received package scope", err)
		}
		if snapshot.Claim.RenewalPolicy != policy {
			t.Fatal("policy gate modified enrollment authority")
		}
	}
}

func TestLegacyCompleteIdentityRetainsNativePackageAuthority(t *testing.T) {
	_, s, _, snapshot, cert := systemLongFixture(t)
	if err := s.AuthorizePackageDevice(context.Background(), snapshot.Approval.DeviceID, "sha256:"+cert.CertificateHash(), time.Unix(snapshot.UpdatedAt, 0).UTC()); err != nil {
		t.Fatal("legacy complete identity lost package authority", err)
	}
}

func TestPackageInitializationInspectionIsReadOnlyAndExact(t *testing.T) {
	f, s, path, snapshot, cert := systemLongFixture(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := directoryContents(t, filepath.Dir(path))
	manager, device, incarnation := snapshot.Binding.InstanceID, snapshot.Approval.DeviceID, "sha256:"+cert.CertificateHash()
	at := time.Unix(snapshot.UpdatedAt, 0).UTC()
	for _, check := range []struct {
		manager, device, incarnation string
		valid                        bool
	}{
		{manager, device, incarnation, true},
		{id("manager", 99), device, incarnation, false},
		{manager, id("agent", 99), incarnation, false},
		{manager, device, "sha256:" + id("wrong", 99), false},
	} {
		err := InspectPackageInitialization(context.Background(), path, f.issuerDER, check.manager, check.device, check.incarnation, at)
		if (err == nil) != check.valid {
			t.Fatal("read-only package initialization binding mismatch", check.valid, err)
		}
	}
	if after := directoryContents(t, filepath.Dir(path)); !reflect.DeepEqual(before, after) {
		t.Fatal("package initialization inspection changed enrollment files or sidecars")
	}
}

func TestWindowsEnrollmentNeverAuthorizesNativePackageDevice(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			_, s, _, v, cert := activeWindowsStore(t, profile)
			if e := s.AuthorizePackageDevice(context.Background(), v.Approval.DeviceID, "sha256:"+cert.CertificateHash(), time.Unix(v.UpdatedAt, 0).UTC()); e == nil {
				t.Fatal("activated Windows scope granted APT authority")
			}
		})
	}
}
