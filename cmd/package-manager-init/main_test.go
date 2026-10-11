package main

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageInitializationRequiresEnrollmentSource(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--config", "/missing/package.json", "--ack-local-package-scope"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "--enrollment-state") || out.Len() != 0 {
		t.Fatal("missing enrollment source was accepted", code, errOut.String())
	}
}

func TestPackageInitializationRejectsPrivateMaterialAsPublicIssuer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	issuer := filepath.Join(dir, "public-issuer.pem")
	// Deliberately non-key fixture bytes: this checks PEM type admission only.
	if err := os.WriteFile(issuer, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a private key")}), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	args := []string{"--config", filepath.Join(dir, "missing-package.json"), "--enrollment-state", filepath.Join(dir, "missing-enrollment.sqlite"), "--enrollment-issuer", issuer, "--ack-local-package-scope"}
	if code := run(args, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "exactly one public certificate") || out.Len() != 0 {
		t.Fatal("private PEM reached initialization", code, errOut.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(issuer) {
		t.Fatal("invalid public input created setup state", err)
	}
}

func TestPackageInitializationPermitsProtectedPublicIssuerPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public-input")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	issuer := filepath.Join(dir, "issuer.pem")
	// DER is intentionally a placeholder: missing package config must stop the
	// operation after public-file admission, before enrollment inspection.
	if err := os.WriteFile(issuer, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("public fixture")}), 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	args := []string{"--config", filepath.Join(dir, "missing-package.json"), "--enrollment-state", filepath.Join(dir, "missing-enrollment.sqlite"), "--enrollment-issuer", issuer, "--ack-local-package-scope"}
	if code := run(args, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "scope initialization failed") || out.Len() != 0 {
		t.Fatal("public issuer unnecessarily required private-file permissions", code, errOut.String())
	}
}
