//go:build linux

package actionhelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func setupFenceFixture(t *testing.T) (authorityFS, Policy, ed25519.PublicKey) {
	t.Helper()
	fs, p, key := authorityFixture(t)
	if err := os.MkdirAll(filepath.Dir(fs.root+SetupIntentPath), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	intent := SetupIntent{Version: SetupIntentVersion, PlanDigest: actionpermit.Digest([]byte("approved fixture plan")), RootPolicyDigest: actionpermit.Digest(raw), KeyID: p.KeyID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest}
	b, _ := json.Marshal(intent)
	authorityWrite(t, fs.root+SetupIntentPath, b, 0600)
	return fs, p, key
}

func TestSetupInitializationFsyncFenceBeforeCreateOnlyLedger(t *testing.T) {
	fs, p, key := setupFenceFixture(t)
	raw, _ := json.Marshal(p)
	ledger := filepath.Join(fs.root, "fixture-ledger")
	initializations := 0
	initialize := func(ctx context.Context, verifier actionpermit.Verifier) error {
		initializations++
		started, err := os.ReadFile(fs.root + SetupStartedPath)
		if err != nil {
			t.Fatal("ledger reached before fence")
		}
		var intent SetupIntent
		if json.Unmarshal(started, &intent) != nil || intent.Version != SetupStartedVersion || intent.RootPolicyDigest != actionpermit.Digest(raw) {
			t.Fatal("unbound fence")
		}
		state, err := actionstate.Initialize(ctx, ledger, verifier)
		if err != nil {
			return err
		}
		return state.Close()
	}
	begin := func(ctx context.Context, p Policy, key ed25519.PublicKey) error {
		return beginSetupInitializationFrom(ctx, fs, p, key)
	}
	identity := func() error { return nil }
	if err := initializeSetupLedger(context.Background(), raw, key, identity, begin, initialize); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(fs.root + SetupStartedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(ledger); err != nil {
		t.Fatal(err)
	}
	if err := initializeSetupLedger(context.Background(), raw, key, identity, begin, initialize); err == nil || initializations != 1 {
		t.Fatal("deleted ledger was reinitialized", err, initializations)
	}
	after, _ := os.ReadFile(fs.root + SetupStartedPath)
	if !bytes.Equal(before, after) {
		t.Fatal("fence changed")
	}
}

func TestSetupInitializationFailurePermanentlyRetainsFence(t *testing.T) {
	fs, p, key := setupFenceFixture(t)
	raw, _ := json.Marshal(p)
	calls := 0
	initialize := func(context.Context, actionpermit.Verifier) error { calls++; return errors.New("fixture failure") }
	begin := func(ctx context.Context, p Policy, key ed25519.PublicKey) error {
		return beginSetupInitializationFrom(ctx, fs, p, key)
	}
	for range 2 {
		if initializeSetupLedger(context.Background(), raw, key, func() error { return nil }, begin, initialize) == nil {
			t.Fatal("failure lost")
		}
	}
	if calls != 1 {
		t.Fatal("failed first initialization retried")
	}
	if _, err := os.Stat(fs.root + SetupStartedPath); err != nil {
		t.Fatal("fence cleaned", err)
	}
}

func TestSetupInitializationRejectsUnboundUnsafeAndExistingFences(t *testing.T) {
	for _, kind := range []string{"missing", "policy", "key", "endpoint", "incarnation", "plan", "unknown", "noncanonical", "mode", "symlink", "hardlink", "directory_mode", "started_empty", "started_symlink", "started_directory", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			fs, p, key := setupFenceFixture(t)
			path := fs.root + SetupIntentPath
			raw, _ := os.ReadFile(path)
			var intent SetupIntent
			json.Unmarshal(raw, &intent)
			ctx := context.Background()
			switch kind {
			case "missing":
				os.Remove(path)
			case "policy":
				intent.RootPolicyDigest = actionpermit.Digest(nil)
			case "key":
				intent.KeyID = actionpermit.Digest(nil)
			case "endpoint":
				intent.EndpointID = "agent_00000000000000000000000000000000"
			case "incarnation":
				intent.IncarnationDigest = actionpermit.Digest(nil)
			case "plan":
				intent.PlanDigest = "unapproved"
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(",\"extra\":true}")...)
				authorityWrite(t, path, raw, 0600)
			case "noncanonical":
				authorityWrite(t, path, append(raw, '\n'), 0600)
			case "mode":
				os.Chmod(path, 0640)
			case "symlink":
				os.Rename(path, path+"-real")
				os.Symlink(path+"-real", path)
			case "hardlink":
				os.Link(path, path+"-link")
			case "directory_mode":
				os.Chmod(filepath.Dir(path), 0755)
			case "started_empty":
				authorityWrite(t, fs.root+SetupStartedPath, nil, 0600)
			case "started_symlink":
				os.Symlink(path, fs.root+SetupStartedPath)
			case "started_directory":
				os.Mkdir(fs.root+SetupStartedPath, 0700)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if kind == "policy" || kind == "key" || kind == "endpoint" || kind == "incarnation" || kind == "plan" {
				raw, _ = json.Marshal(intent)
				authorityWrite(t, path, raw, 0600)
			}
			if err := beginSetupInitializationFrom(ctx, fs, p, key); err == nil {
				t.Fatal("accepted", kind)
			}
			if kind != "started_empty" && kind != "started_symlink" && kind != "started_directory" {
				if _, err := os.Lstat(fs.root + SetupStartedPath); !os.IsNotExist(err) {
					t.Fatal("invalid intent created fence")
				}
			}
		})
	}
}

func TestSetupTargetCheckOnlyFixedReadOnlyBackend(t *testing.T) {
	a, _ := fixtureAuthority()
	target := a.Policy.Targets[0]
	props := fixtureProperties()
	target.Units[0].ConfigurationDigest = configurationDigest(props)
	calls := 0
	backend := &systemdBackend{input: func(FilePin) error { return nil }, run: func(_ context.Context, args []string) ([]byte, error) {
		calls++
		if reflect.DeepEqual(args, systemctlArgs("show", target.Unit, configurationProperties)) {
			return propertiesOutput(props, configurationProperties), nil
		}
		if reflect.DeepEqual(args, systemctlArgs("show", target.Unit, []string{"Id", "ActiveState"})) {
			return []byte("Id=fixture.service\nActiveState=active\n"), nil
		}
		t.Fatal("setup target invoked non-show operation", args)
		return nil, ErrRejected
	}}
	result, err := checkSetupTarget(context.Background(), target, func() error { return nil }, backend.Check)
	want, _ := targetDigest(target)
	if err != nil || calls != 2 || result.UnitPolicyDigest != want || result.ObservedState != Active || !reflect.DeepEqual(result.Target, target) {
		t.Fatal(result, err, calls)
	}
	digest, err := SetupConfigurationDigest(propertiesOutput(props, configurationProperties))
	if err != nil || digest != target.Units[0].ConfigurationDigest {
		t.Fatal("fingerprint mismatch")
	}
}

func TestSetupTargetFileIsProtectedAndStable(t *testing.T) {
	for _, kind := range []string{"valid", "noncanonical", "unknown", "mode", "symlink", "changed"} {
		t.Run(kind, func(t *testing.T) {
			fs, p, _ := authorityFixture(t)
			name := "/etc/tracebolt/target-review.json"
			raw, _ := json.Marshal(p.Targets[0])
			if kind == "noncanonical" {
				raw = append(raw, '\n')
			}
			if kind == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(",\"command\":\"danger\"}")...)
			}
			authorityWrite(t, fs.root+name, raw, 0600)
			if kind == "mode" {
				os.Chmod(fs.root+name, 0644)
			}
			if kind == "symlink" {
				os.Rename(fs.root+name, fs.root+name+"-real")
				os.Symlink(fs.root+name+"-real", fs.root+name)
			}
			calls := 0
			_, err := checkSetupTargetFileFrom(context.Background(), fs, name, func(_ context.Context, target Target) (SetupTargetResult, error) {
				calls++
				if kind == "changed" {
					authorityWrite(t, fs.root+name, append(raw, '\n'), 0600)
				}
				return SetupTargetResult{Target: target}, nil
			})
			if (err == nil) != (kind == "valid") {
				t.Fatal(kind, err)
			}
			if kind != "valid" && kind != "changed" && calls != 0 {
				t.Fatal("unsafe review reached backend")
			}
		})
	}
}

func TestSetupInitializationRequiresRootAndCanonicalPolicyBeforeFence(t *testing.T) {
	a, _ := fixtureAuthority()
	raw, _ := json.Marshal(a.Policy)
	for _, kind := range []string{"identity", "policy", "key", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			identity := func() error { return nil }
			body := raw
			key := a.PublicKey
			switch kind {
			case "identity":
				identity = func() error { return ErrRejected }
			case "policy":
				body = append(append([]byte(nil), raw...), ' ')
			case "key":
				key = make([]byte, ed25519.PublicKeySize)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := initializeSetupLedger(ctx, body, key, identity, func(context.Context, Policy, ed25519.PublicKey) error {
				t.Fatal("invalid initializer reached fence")
				return nil
			}, func(context.Context, actionpermit.Verifier) error {
				t.Fatal("invalid initializer reached state")
				return nil
			})
			if err == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}

func TestSetupInitializationRetainedCompletionBlocksLostLedgerAndStarted(t *testing.T) {
	for _, kind := range []string{"valid", "malformed", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			fs, p, key := setupFenceFixture(t)
			// Simulate only completion evidence surviving a partial-loss incident. Neither
			// a used ledger nor the independent started fence is available for adoption.
			path := fs.root + SetupCompletePath
			switch kind {
			case "valid":
				authorityWrite(t, path, []byte(`{"version":"tracebolt.action-setup-complete.v1"}`), 0600)
			case "malformed":
				authorityWrite(t, path, []byte("partial"), 0600)
			case "symlink":
				if e := os.Symlink(fs.root+SetupIntentPath, path); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if beginSetupInitializationFrom(context.Background(), fs, p, key) == nil {
				t.Fatal("completion evidence was adopted")
			}
			if _, e := os.Lstat(fs.root + SetupStartedPath); !os.IsNotExist(e) {
				t.Fatal("created replacement started fence")
			}
		})
	}
}
