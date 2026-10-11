package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentclient"
	"reflect"
	"strings"
	"testing"
)

func TestFreshWizardRenewalConsentIsExactAndPreservesTwentyScopes(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, renewable := range []bool{false, true} {
			b, _ := setupPublicBootstrapFixture(t, transport)
			if renewable {
				b.SchemaVersion = enrollmentclient.RenewableBootstrapVersion
				b.RenewalPolicy = "same-key-v1"
			}
			raw, _ := json.Marshal(b)
			preview, err := setupWizardPreview(raw)
			if transport == "http-test" && renewable {
				if err == nil {
					t.Fatal("HTTP renewal preview")
				}
				continue
			}
			if err != nil || preview.AutomaticRenewal != renewable {
				t.Fatal("renewal preview")
			}
			for _, acknowledged := range []bool{false, true} {
				_, consent, err := setupWizardReadAdminAcknowledgedBootstrap(raw, transport == "http-test", acknowledged)
				if (err == nil) != (renewable == acknowledged) {
					t.Fatal("renewal acknowledgement mismatch")
				}
				if err == nil && !reflect.DeepEqual(consent, freshReadAdminSetupConsent(transport == "http-test")) {
					t.Fatal("renewal changed read scopes/receipt")
				}
			}
		}
	}
}

func TestRenewalLifecycleFlagIsFreshTLSOnlyAndDisclosed(t *testing.T) {
	for _, tail := range [][]string{{"--insecure-http-test"}, {"--restart", "--apply"}, {"--read-admin-enable", "--apply", "--twelve-read-admin-scopes"}} {
		var out, stderr bytes.Buffer
		calls := 0
		args := append([]string{"--automatic-certificate-renewal"}, tail...)
		if runWith(context.Background(), args, &out, &stderr, func(context.Context, request, io.Writer, io.Writer) (any, error) { calls++; return nil, nil }) != 2 || calls != 0 {
			t.Fatal("renewal widened existing/HTTP action")
		}
	}
	var out, stderr bytes.Buffer
	calls := 0
	args := []string{"--install", "--apply", "--windows-inventory", "--bootstrap-file=C:\\Fixture\\bootstrap.json", "--automatic-certificate-renewal"}
	if runWith(context.Background(), args, &out, &stderr, func(_ context.Context, r request, _, _ io.Writer) (any, error) {
		calls++
		if !r.automaticRenewal || !strings.Contains(out.String(), enrollmentclient.AutomaticRenewalPrivacy) {
			t.Fatal("renewal lost or not disclosed")
		}
		return nil, nil
	}) != 0 || calls != 1 {
		t.Fatal("fresh renewal flag")
	}
}
