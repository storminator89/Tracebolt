//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"os"
	"path/filepath"
	"testing"
)

func writerLeaseMaterial(t *testing.T, state string) lanconfig.Material {
	t.Helper()
	// Synthetic in-memory verifier shape only; no login, account, certificate,
	// key, listener or credential file is created by these fixtures.
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)) + "$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.HTTPTest, OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444", OperatorOrigin: "http://127.0.0.1:8443", AgentOrigin: "http://127.0.0.1:8444", AgentClientCAFile: filepath.Join(state, "never-read-ca"), OperatorAuthFile: filepath.Join(state, "never-read-auth"), StateDirectory: state, WebDirectory: filepath.Join(state, "never-read-web"), InsecureHTTPAcknowledged: true}
	return lanconfig.Material{Config: c, PasswordHash: encoded}
}

func TestManagerWriterLeaseBlocksBeforeProfileOrDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old := []byte("invented old database; must not open")
	if err := os.WriteFile(filepath.Join(dir, "agents.db"), old, 0600); err != nil {
		t.Fatal(err)
	}
	lease, err := lanstore.AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	p, err := prepare(writerLeaseMaterial(t, dir))
	if p != nil {
		p.close()
		t.Fatal("duplicate writer prepared")
	}
	if !errors.Is(err, lanstore.ErrManagerWriterBusy) {
		t.Fatal("writer lease did not win before invalid profile/database/CA", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "agents.db"))
	entries, listErr := os.ReadDir(dir)
	if err != nil || !bytes.Equal(got, old) || listErr != nil || len(entries) != 1 {
		t.Fatal("denied preparation changed retained state")
	}
}

func TestManagerWriterLeasePreparationFailureReleasesAfterStoreClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	p, err := prepare(writerLeaseMaterial(t, dir))
	if p != nil {
		p.close()
		t.Fatal("invalid CA prepared")
	}
	if err == nil || errors.Is(err, lanstore.ErrManagerWriterBusy) {
		t.Fatal("deliberately invalid material did not fail at preparation")
	}
	lease, err := lanstore.AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal("failed preparation retained the writer lease", err)
	}
	defer lease.Close()
	// The failure path closed the opened store, rather than leaking it merely
	// to release the root lease. Reopening existing fixture state must succeed.
	store, err := lanstore.Open(filepath.Join(dir, "agents.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerWriterLeaseStartupFilesystemCompatibilityOnly(t *testing.T) {
	for _, failure := range []error{lanstore.ErrManagerWriterUnavailable, lanstore.ErrManagerWriterBusy, lanstore.ErrStorage, lanstore.ErrRestoreQuarantined, errors.Join(lanstore.ErrManagerWriterUnavailable, lanstore.ErrManagerWriterBusy), errors.Join(lanstore.ErrManagerWriterUnavailable, lanstore.ErrStorage)} {
		called := false
		lease, err := startupManagerWriterLease("synthetic-private-directory", func(dir string) (lanstore.ManagerWriterLease, error) {
			called = dir == "synthetic-private-directory"
			return nil, failure
		})
		want := failure
		if failure == lanstore.ErrManagerWriterUnavailable {
			want = nil
		}
		if !called || lease != nil || err != want {
			t.Fatal("filesystem compatibility fallback suppressed a real denial")
		}
	}
}
