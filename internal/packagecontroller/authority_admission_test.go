//go:build linux

package packagecontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packagewire"
)

type forbiddenAuthorityStore struct {
	opened, written bool
}

func (s *forbiddenAuthorityStore) Open(context.Context, packageupdate.Binding) ([]byte, error) {
	s.opened = true
	return nil, errors.New("unexpected package store open")
}
func (s *forbiddenAuthorityStore) CompareAndSwap(context.Context, packageupdate.Binding, uint64, []byte) error {
	s.written = true
	return errors.New("unexpected package store write")
}

func TestAuthorityDenialPrecedesManagerStoreAdmission(t *testing.T) {
	f := fixture(t)
	denied := errors.New("renewable identity does not support native package actions")
	store := &forbiddenAuthorityStore{}
	authority := func(context.Context, string, string, time.Time) error { return denied }
	actor := func(string, operatorauth.Capability) bool { return true }
	if _, err := newManager(ctx, f.config, f.key, store, authority, actor, func() time.Time { return f.at }); !errors.Is(err, denied) {
		t.Fatal("authority error was not preserved", err)
	}
	if store.opened || store.written {
		t.Fatal("unsupported setup touched package persistence")
	}

	// Runtime construction must reject before key or SQLite admission, not
	// merely reject later operations after a durable active-session write.
	c := f.config
	c.StateFile = filepath.Join(filepath.Dir(c.StateFile), "unsupported.sqlite")
	before := []byte("disposable untouched package-store sentinel")
	if err := os.WriteFile(c.StateFile, before, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	path := filepath.Join(filepath.Dir(c.StateFile), "unsupported.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, path, authority, actor); !errors.Is(err, denied) {
		t.Fatal("runtime setup reached protected key/store before authority", err)
	}
	after, err := os.ReadFile(c.StateFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unsupported runtime setup changed package bytes", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(c.StateFile + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unsupported runtime setup opened SQLite sidecar", suffix, err)
		}
	}
}

func TestAuthorityDenialPrecedesEveryNativePackageOperation(t *testing.T) {
	f := fixture(t)
	result := f.prep(t)
	claim := packagewire.Identity{JobID: f.req.RequestID, Sequence: 1, Kind: packagepermit.Prepare, EnvelopeDigest: result.PreparationEnvelopeDigest}
	denied := errors.New("renewable identity does not support native package actions")
	f.m.device = func(context.Context, string, string, time.Time) error { return denied }
	store := &forbiddenAuthorityStore{}
	f.m.store = store
	checks := []struct {
		name string
		run  func() error
	}{
		{"report", func() error { return f.m.Report(ctx, f.config.EndpointID, f.config.IncarnationDigest, f.caps) }},
		{"prepare", func() error { return f.m.Prepare(ctx, f.config.EndpointID, actor, f.req) }},
		{"approve", func() error { return f.m.Approve(ctx, f.config.EndpointID, actor, packageupdate.ApprovalRequest{}) }},
		{"peek", func() error { _, err := f.m.Peek(ctx, f.config.EndpointID, f.config.IncarnationDigest); return err }},
		{"claim", func() error {
			_, err := f.m.Claim(ctx, f.config.EndpointID, f.config.IncarnationDigest, claim)
			return err
		}},
		{"accept", func() error { return f.m.Accept(ctx, f.config.EndpointID, f.config.IncarnationDigest, result) }},
		{"view", func() error { _, err := f.m.View(ctx, f.config.EndpointID, f.at); return err }},
		{"view-job", func() error { _, err := f.m.ViewJob(ctx, f.config.EndpointID, f.req.RequestID, f.at); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, denied) {
				t.Fatal("operation bypassed identity policy", err)
			}
			if store.opened || store.written {
				t.Fatal("unsupported operation touched package persistence")
			}
		})
	}
}

func TestInitializationRequiresExactAuthorityBeforeKeyOrStoreAccess(t *testing.T) {
	f := fixture(t)
	c := f.config
	c.StateFile = filepath.Join(filepath.Dir(c.StateFile), "denied-initialization.sqlite")
	c.PrivateKeyFile = filepath.Join(filepath.Dir(c.StateFile), "absent-private-key")
	raw, _ := json.Marshal(c)
	path := filepath.Join(filepath.Dir(c.StateFile), "denied-initialization.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(ctx, path, true, f.at); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing read-only enrollment authority was accepted", err)
	}
	if err := Initialize(ctx, path, true, f.at, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil enrollment authority was accepted", err)
	}
	denied := errors.New("renewable enrollment source denies package initialization")
	called := false
	authority := func(_ context.Context, manager, device, incarnation string, now time.Time) error {
		called = true
		if manager != c.ManagerID || device != c.EndpointID || incarnation != c.IncarnationDigest || !now.Equal(f.at) {
			t.Fatal("initialization did not bind its exact configured identity")
		}
		return denied
	}
	if err := Initialize(ctx, path, true, f.at, authority); !errors.Is(err, denied) || !called {
		t.Fatal("initialization read key or admitted persistence before authority", err)
	}
	for _, target := range []string{c.PrivateKeyFile, c.StateFile, c.StateFile + "-wal", c.StateFile + "-shm", c.StateFile + "-journal"} {
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("denied initialization created state", target, err)
		}
	}
}
