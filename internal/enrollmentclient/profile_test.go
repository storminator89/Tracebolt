//go:build linux

package enrollmentclient

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFreshOperationalEnrollmentHandoffAndPrivacy(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newClientFixture(t, profile, enrollmentcrypto.CollectionProfileOperational)
			options := f.options()
			displayed := false
			options.Display = func(d TrustDisplay) error {
				for _, category := range []string{"volume", "network", "service", "process", "package", "event", "secret-like", "not anonymous", "AI"} {
					if !strings.Contains(d.CollectionPrivacy, category) {
						t.Error("missing privacy category", category)
					}
				}
				if d.CollectionProfile != enrollmentcrypto.CollectionProfileOperational {
					t.Error("wrong collection display")
				}
				displayed = true
				return nil
			}
			options.Secret = func(context.Context) ([]byte, error) {
				if !displayed {
					t.Error("secret before privacy")
				}
				return []byte(f.secret), nil
			}
			result, err := Run(context.Background(), f.bootstrap, options)
			if err != nil {
				t.Fatal("fresh operational enrollment", err)
			}
			if result.Config.SchemaVersion != lanclient.OperationalConfigVersion || result.Config.CollectionProfile != enrollmentcrypto.CollectionProfileOperational {
				t.Fatal("wrong operational handoff")
			}
			if lanclient.ValidateGuidedHandoff(result.ConfigPath) != nil {
				t.Fatal("operational ready preflight rejected")
			}
			before, _ := os.ReadFile(result.ConfigPath)
			changed := f.bootstrap
			changed.CollectionProfile = enrollmentcrypto.CollectionProfile
			if _, err := Run(context.Background(), changed, options); !errors.Is(err, ErrState) {
				t.Fatal("existing profile silently changed")
			}
			after, _ := os.ReadFile(result.ConfigPath)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected switch changed handoff")
			}
		})
	}
}

func TestBasicHandoffRetainsOriginalSerializedShape(t *testing.T) {
	f := newClientFixture(t, "http-test")
	result, err := Run(context.Background(), f.bootstrap, f.options())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.ConfigPath)
	if err != nil || bytes.Contains(raw, []byte("collectionProfile")) || result.Config.SchemaVersion != lanclient.GuidedConfigVersion || result.Config.CollectionProfile != "" {
		t.Fatal("basic config expanded")
	}
	d, err := validateBootstrap(f.bootstrap, time.Now())
	if err != nil || d.CollectionPrivacy != "" {
		t.Fatal("basic privacy display changed")
	}
}

func TestFreshPackageEnrollmentHandoffAndExpandedPrivacy(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newClientFixture(t, transport, enrollmentcrypto.CollectionProfilePackages)
			options := f.options()
			displayed := false
			options.Display = func(d TrustDisplay) error {
				for _, text := range []string{"OS release", "source package", "source-mapping", "partial", "until replaced", "after revocation", "excluded from AI", "cannot be adopted"} {
					if !strings.Contains(d.CollectionPrivacy, text) {
						t.Error("missing package privacy boundary", text)
					}
				}
				if d.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
					t.Error("wrong package profile")
				}
				displayed = true
				return nil
			}
			options.Secret = func(context.Context) ([]byte, error) {
				if !displayed {
					t.Error("invitation before scope display")
				}
				return []byte(f.secret), nil
			}
			result, e := Run(context.Background(), f.bootstrap, options)
			if e != nil {
				t.Fatal("package enrollment", e)
			}
			if result.Config.SchemaVersion != lanclient.PackageConfigVersion || result.Config.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || lanclient.ValidateGuidedHandoff(result.ConfigPath) != nil {
				t.Fatal("package handoff invalid")
			}
			before, _ := os.ReadFile(result.ConfigPath)
			for _, old := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational} {
				changed := f.bootstrap
				changed.CollectionProfile = old
				if _, e := Run(context.Background(), changed, options); !errors.Is(e, ErrState) {
					t.Fatal("package state silently adopted old profile", e)
				}
				after, _ := os.ReadFile(result.ConfigPath)
				if !bytes.Equal(before, after) {
					t.Fatal("rejected profile rewrote config")
				}
			}
		})
	}
}
