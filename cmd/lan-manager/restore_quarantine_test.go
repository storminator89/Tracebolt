//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreQuarantineStopsEveryPreparationBeforeStateOrAuthority(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"profile", "agents.db", "enrollment-v2.db", "enrollment-v2.db-wal", "operator.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("invented old snapshot; never opened"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := lanstore.MarkRestoreQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	// No credentials, issuers, authenticated actors or network fixtures. Material
	// is deliberately invalid: quarantine must win before any material/store use.
	m := lanconfig.Material{Config: lanconfig.Config{StateDirectory: dir}}
	for name, call := range map[string]func() error{
		"prepare": func() error {
			p, err := prepare(m)
			if p != nil {
				p.close()
				return errors.New("prepared quarantined state")
			}
			return err
		},
		"prepare-enrollment": func() error { _, err := prepareWithEnrollment(m, nil); return err },
		"prepare-alarms":     func() error { _, err := prepareWithAlarms(m, nil, alarmdelivery.Config{}); return err },
		"prepare-checks": func() error {
			_, err := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, applicationcheck.Config{})
			return err
		},
		"run":            func() error { return run(context.Background(), m) },
		"run-enrollment": func() error { return runWithEnrollment(context.Background(), m, nil) },
		"run-alarms":     func() error { return runWithAlarms(context.Background(), m, nil, alarmdelivery.Config{}) },
		"run-checks": func() error {
			return runWithApplicationChecks(context.Background(), m, nil, alarmdelivery.Config{}, applicationcheck.Config{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, lanstore.ErrRestoreQuarantined) {
				t.Fatal("quarantine boundary bypassed", err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 6 {
		t.Fatal("preparation changed snapshot entries", err)
	}
	for _, name := range []string{"profile", "agents.db", "enrollment-v2.db", "enrollment-v2.db-wal", "operator.db"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(raw) != "invented old snapshot; never opened" {
			t.Fatal("quarantined bytes changed", name, err)
		}
	}
}

func TestRestoreQuarantineStopsStartupBeforeCredentialLoading(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := lanstore.MarkRestoreQuarantine(state); err != nil {
		t.Fatal(err)
	}
	c := lanconfig.Config{
		SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS,
		OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444",
		OperatorOrigin: "https://manager.example.invalid:8443", AgentOrigin: "https://manager.example.invalid:8444",
		TLSCertificateFile: filepath.Join(dir, "missing-server.pem"), TLSPrivateKeyFile: filepath.Join(dir, "missing-server.key"),
		AgentClientCAFile: filepath.Join(dir, "missing-ca.pem"), OperatorAuthFile: filepath.Join(dir, "missing-auth.json"),
		StateDirectory: state, WebDirectory: filepath.Join(dir, "missing-web"),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lan.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadStartupMaterial(path); !errors.Is(err, lanstore.ErrRestoreQuarantined) {
		t.Fatal("startup loaded material before checking quarantine", err)
	}
}
