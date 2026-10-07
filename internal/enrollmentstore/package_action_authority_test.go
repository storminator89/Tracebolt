package enrollmentstore

import (
	"context"
	"testing"
	"time"
)

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
