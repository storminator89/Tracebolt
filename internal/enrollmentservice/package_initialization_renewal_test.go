package enrollmentservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/packagecontroller"
)

func TestRenewablePackageInitializationFailsBeforeWrites(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewal-enabled", true: "renewal-disabled"}[disabled], func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, "tls", true)
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			// This is a distinct fresh fixture identity, never migration or reset
			// of the original fixture database.
			f.path = filepath.Join(t.TempDir(), "complete", "enrollment.sqlite")
			f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
			var err error
			f.store, err = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
			if err != nil {
				t.Fatal(err)
			}
			f.service, err = New(f.store, f.issuer, func() time.Time { return f.now })
			if err != nil {
				t.Fatal(err)
			}
			pending, key := claimForPlatform(t, f, "linux")
			if _, err = f.service.Approve(ctx, pending.InvitationID, id("request", 4), pending.Claim.KeyFingerprint, pending.Revision); err != nil {
				t.Fatal(err)
			}
			statusChallenge, body := status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 5, key)
			if _, err = f.service.Status(ctx, statusChallenge.Context.Challenge, body); err != nil {
				t.Fatal(err)
			}
			cert, err := f.store.CertificateForVerification(ctx, pending.InvitationID)
			if err != nil {
				t.Fatal(err)
			}
			c := challenge(t, f, pending.InvitationID, pending.Claim.ClaimID, "activation")
			message, err := enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), id("request", 7), cert.CertificateHash(), f.now)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": id("request", 7), "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
			active, err := f.service.Activate(ctx, c.Context.Challenge, body)
			if err != nil {
				t.Fatal(err)
			}
			if disabled {
				if _, err = f.service.DisableRenewal(ctx, active.InvitationID, id("request", 120), active.Revision); err != nil {
					t.Fatal(err)
				}
			}
			incarnation := "sha256:" + active.Issuance.CertificateHash
			if err = f.store.AuthorizePackageDevice(ctx, active.Approval.DeviceID, incarnation, f.now); !errors.Is(err, enrollmentstore.ErrPackageRenewalUnsupported) {
				t.Fatal("renewable identity received native package authority", err)
			}
			if _, err = f.store.AuthorizeCertificate(ctx, cert.DER(), f.now); err != nil {
				t.Fatal("package boundary revoked read-admin transport", err)
			}
			if err = f.store.Close(); err != nil {
				t.Fatal(err)
			}
			before := packageBoundaryFiles(t, filepath.Dir(f.path))
			if err = enrollmentstore.InspectPackageInitialization(ctx, f.path, f.issuer.IssuerDER(), active.Binding.InstanceID, active.Approval.DeviceID, incarnation, f.now); !errors.Is(err, enrollmentstore.ErrPackageRenewalUnsupported) {
				t.Fatal("read-only setup inspector promoted renewable identity", err)
			}
			dir := filepath.Join(t.TempDir(), "package")
			if err = os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			config := packagecontroller.Config{Version: packagecontroller.ConfigVersion, Enabled: true, ManagerID: active.Binding.InstanceID, EndpointID: active.Approval.DeviceID, IncarnationDigest: incarnation, RootPolicyDigest: actionpermit.Digest([]byte("disposable package initialization boundary")), TransportProfile: "production-tls", StateFile: filepath.Join(dir, "packages.sqlite"), PrivateKeyFile: filepath.Join(dir, "missing-key"), LocalScopeAcknowledged: true}
			raw, _ := json.Marshal(config)
			configPath := filepath.Join(dir, "package.json")
			if err = os.WriteFile(configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			packageBefore := packageBoundaryFiles(t, dir)
			authority := func(ctx context.Context, manager, device, incarnation string, at time.Time) error {
				return enrollmentstore.InspectPackageInitialization(ctx, f.path, f.issuer.IssuerDER(), manager, device, incarnation, at)
			}
			if err = packagecontroller.Initialize(ctx, configPath, true, f.now, authority); !errors.Is(err, enrollmentstore.ErrPackageRenewalUnsupported) {
				t.Fatal("initialization reached missing key or package persistence before policy denial", err)
			}
			if !reflect.DeepEqual(before, packageBoundaryFiles(t, filepath.Dir(f.path))) || !reflect.DeepEqual(packageBefore, packageBoundaryFiles(t, dir)) {
				t.Fatal("unsupported initialization changed enrollment or package files")
			}
		})
	}
}

func packageBoundaryFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = raw
	}
	return out
}
