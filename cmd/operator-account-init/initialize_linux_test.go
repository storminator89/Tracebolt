//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/operatorauth"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

type initFixture struct {
	o            options
	c            lanconfig.Config
	seed, config []byte
}

func writeFixture(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func newInitFixture(t *testing.T) initFixture {
	t.Helper()
	d := t.TempDir()
	for _, name := range []string{"state", "private", "web"} {
		if err := os.Mkdir(filepath.Join(d, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS, OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444", OperatorOrigin: "https://manager.invalid:8443", AgentOrigin: "https://manager.invalid:8444", TLSCertificateFile: filepath.Join(d, "cert"), TLSPrivateKeyFile: filepath.Join(d, "key"), AgentClientCAFile: filepath.Join(d, "ca"), OperatorAuthFile: filepath.Join(d, "private", "seed.json"), StateDirectory: filepath.Join(d, "state"), WebDirectory: filepath.Join(d, "web")}
	// Deliberately non-login fixture verifiers, never real provisioned secrets.
	hash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("synthetic-salt-12")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ops := make([]map[string]any, 4)
	for i := range ops {
		ops[i] = map[string]any{"id": fmt.Sprintf("operator_%032x", i+1), "username": fmt.Sprintf("fixture%d", i), "passwordHash": hash, "capabilities": []string{"read", "manage_accounts"}}
	}
	seed, err := json.Marshal(map[string]any{"schemaVersion": "tracebolt.operator-auth.v2", "profile": "tls", "operators": ops})
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	o := options{lanConfig: filepath.Join(d, "private", "lan.json"), output: filepath.Join(d, "private", "live.json"), runtimeUID: os.Geteuid(), acknowledge: true}
	writeFixture(t, c.OperatorAuthFile, seed)
	writeFixture(t, o.lanConfig, config)
	// Fail rather than skip on unsupported ownership. Never weaken public guards.
	if _, err := lanconfig.LoadConfig(o.lanConfig); err != nil {
		t.Fatalf("public protected fixture unavailable: %v", err)
	}
	if !privateDirectory(c.StateDirectory) || !privateDirectory(filepath.Dir(o.output)) {
		t.Fatal("public protected fixture ancestors rejected")
	}
	if _, err := lanconfig.LoadNamedOperatorSeed(c.OperatorAuthFile, c.Profile); err != nil {
		t.Fatalf("public seed fixture rejected: %v", err)
	}
	return initFixture{o, c, seed, config}
}
func (f initFixture) paths() []string {
	return []string{filepath.Join(f.c.StateDirectory, lanconfig.AccountAuthorityMarkerFile), filepath.Join(f.c.StateDirectory, lanconfig.AccountAuthorityJournalFile), f.o.output}
}
func assertAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("unexpected destination state: %s (%v)", filepath.Base(p), err)
		}
	}
}
func TestInitializeCreatesPinnedAuthorityOnce(t *testing.T) {
	f := newInitFixture(t)
	if got := initialize(f.o); got != "created" {
		t.Fatalf("initialize: %s", got)
	}
	saved := make(map[string][]byte)
	for _, p := range f.paths() {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		saved[p] = raw
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			t.Fatal("nonprivate output")
		}
	}
	ref, err := lanconfig.ParseAccountAuthority(saved[f.o.output], lanconfig.TLS)
	if err != nil {
		t.Fatal(err)
	}
	if err := lanconfig.CheckAccountAuthorityMarker(f.c.StateDirectory, ref); err != nil {
		t.Fatal(err)
	}
	if lanconfig.CheckAccountAuthorityMarker(f.c.StateDirectory, nil) == nil {
		t.Fatal("legacy downgrade accepted")
	}
	j, err := operatorauth.OpenAccountJournal(ref.AuthorityFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := j.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	seed, err := lanconfig.LoadNamedOperatorSeed(f.c.OperatorAuthFile, lanconfig.TLS)
	if err != nil {
		t.Fatal(err)
	}
	if s.Revision != 1 || s.AuthorityID != ref.AuthorityID || s.Profile != lanconfig.TLS || len(s.Accounts) != len(seed) {
		t.Fatal("initial authority mismatch")
	}
	for i, a := range s.Accounts {
		want, _ := json.Marshal(seed[i])
		got, _ := json.Marshal(a.Operator)
		if !bytes.Equal(want, got) || a.Revision != 1 || a.RevocationFloor != 0 || a.Disabled {
			t.Fatal("seed authority changed")
		}
	}
	if got := initialize(f.o); got != "existing_authority" {
		t.Fatalf("retry: %s", got)
	}
	saved[f.o.lanConfig] = f.config
	saved[f.c.OperatorAuthFile] = f.seed
	for p, want := range saved {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("existing material changed")
		}
	}
}

func TestInitializeRetainsInterruptedAndExistingStates(t *testing.T) {
	// Model every durable prefix and orphaned/malformed destination. These are
	// restart fixtures, not a claim that power-loss durability was exercised.
	for _, mask := range []int{1, 2, 3, 4, 5, 6, 7} {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			f := newInitFixture(t)
			paths := f.paths()
			raw := []byte("incomplete-retained-state\n")
			for i, p := range paths {
				if mask&(1<<i) != 0 {
					writeFixture(t, p, raw)
				}
			}
			if got := initialize(f.o); got != "existing_authority" {
				t.Fatalf("partial retry: %s", got)
			}
			for i, p := range paths {
				if mask&(1<<i) == 0 {
					assertAbsent(t, p)
				} else {
					got, err := os.ReadFile(p)
					if err != nil || !bytes.Equal(got, raw) {
						t.Fatal("partial state replaced")
					}
				}
			}
		})
	}
}
func TestInitializeRefusesSecondManagerWriter(t *testing.T) {
	f := newInitFixture(t)
	lease, err := lanstore.AcquireManagerWriter(f.c.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if got := initialize(f.o); got != "manager_writer" {
		t.Fatalf("second writer: %s", got)
	}
	assertAbsent(t, f.paths()...)
}
func TestInitializeRefusesSymlinkDestinations(t *testing.T) {
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newInitFixture(t)
			paths := f.paths()
			target := filepath.Join(filepath.Dir(f.o.output), "missing-target")
			if err := os.Symlink(target, paths[i]); err != nil {
				t.Fatal(err)
			}
			if got := initialize(f.o); got != "existing_authority" {
				t.Fatalf("symlink: %s", got)
			}
			got, err := os.Readlink(paths[i])
			if err != nil || got != target {
				t.Fatal("symlink changed")
			}
			assertAbsent(t, target)
			for n, p := range paths {
				if n != i {
					assertAbsent(t, p)
				}
			}
		})
	}
}
func TestInitializeRefusesUnprotectedSeedAndDirectory(t *testing.T) {
	for _, which := range []string{"seed", "state", "output_parent"} {
		t.Run(which, func(t *testing.T) {
			f := newInitFixture(t)
			p := f.c.OperatorAuthFile
			mode := os.FileMode(0644)
			want := "named_seed"
			if which != "seed" {
				mode = 0755
				want = "protected_directories"
				p = f.c.StateDirectory
				if which == "output_parent" {
					p = filepath.Dir(f.o.output)
				}
			}
			// Only this disposable fixture is made less protected to test rejection.
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			if got := initialize(f.o); got != want {
				t.Fatalf("protection: got %s want %s", got, want)
			}
			assertAbsent(t, f.paths()...)
		})
	}
}

func TestInitializePartialJournalFailure(t *testing.T) {
	if os.Getenv("TRACEBOLT_INIT_LIMIT_CHILD") == "1" {
		signal.Ignore(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 512, Max: 512}); err != nil {
			t.Fatal(err)
		}
		o := options{lanConfig: os.Getenv("TRACEBOLT_INIT_CONFIG"), output: os.Getenv("TRACEBOLT_INIT_OUTPUT"), runtimeUID: os.Geteuid(), acknowledge: true}
		if got := initialize(o); got != "journal_uncertain" {
			t.Fatalf("limited initialize: %s", got)
		}
		return
	}
	f := newInitFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestInitializePartialJournalFailure$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_INIT_LIMIT_CHILD=1", "TRACEBOLT_INIT_CONFIG="+f.o.lanConfig, "TRACEBOLT_INIT_OUTPUT="+f.o.output)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated file-size failure fixture: %v (%s)", err, out)
	}
	paths := f.paths()
	marker, err := os.ReadFile(paths[0])
	if err != nil || !json.Valid(marker) {
		t.Fatal("durable first marker missing")
	}
	partial, err := os.ReadFile(paths[1])
	if err != nil || len(partial) != 512 {
		t.Fatal("expected retained partial journal")
	}
	assertAbsent(t, paths[2])
	if lanconfig.CheckAccountAuthorityMarker(f.c.StateDirectory, nil) == nil {
		t.Fatal("partial failure allowed static fallback")
	}
	if j, err := operatorauth.OpenAccountJournal(paths[1]); err == nil {
		j.Close()
		t.Fatal("partial journal opened")
	}
	if got := initialize(f.o); got != "existing_authority" {
		t.Fatalf("partial failure retry: %s", got)
	}
	for p, want := range map[string][]byte{paths[0]: marker, paths[1]: partial, f.o.lanConfig: f.config, f.c.OperatorAuthFile: f.seed} {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("uncertain state changed")
		}
	}
}

func TestInitializeRefusesSymlinkSeedAndDirectories(t *testing.T) {
	for _, which := range []string{"seed", "state", "output_parent"} {
		t.Run(which, func(t *testing.T) {
			f := newInitFixture(t)
			p := f.c.OperatorAuthFile
			want := "named_seed"
			if which == "state" {
				p = f.c.StateDirectory
				want = "protected_directories"
			}
			if which == "output_parent" {
				p = filepath.Dir(f.o.output)
				// The configuration itself also lives in this directory.
				want = "lan_config"
			}
			target := p + "-retained"
			if err := os.Rename(p, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			if got := initialize(f.o); got != want {
				t.Fatalf("symlink protection: got %s want %s", got, want)
			}
			if got, err := os.Readlink(p); err != nil || got != target {
				t.Fatal("protected symlink replaced")
			}
			assertAbsent(t, f.paths()...)
		})
	}
}

func TestInitializeRefusesServedOrStateOutput(t *testing.T) {
	for _, which := range []string{"state", "web", "seed", "config"} {
		t.Run(which, func(t *testing.T) {
			f := newInitFixture(t)
			switch which {
			case "state":
				f.o.output = filepath.Join(f.c.StateDirectory, "live.json")
			case "web":
				f.o.output = filepath.Join(f.c.WebDirectory, "live.json")
			case "seed":
				f.o.output = f.c.OperatorAuthFile
			case "config":
				f.o.output = f.o.lanConfig
			}
			if got := initialize(f.o); got != "path_separation" {
				t.Fatalf("path separation: %s", got)
			}
			assertAbsent(t, filepath.Join(f.c.StateDirectory, lanconfig.AccountAuthorityMarkerFile), filepath.Join(f.c.StateDirectory, lanconfig.AccountAuthorityJournalFile))
			for p, want := range map[string][]byte{f.o.lanConfig: f.config, f.c.OperatorAuthFile: f.seed} {
				got, err := os.ReadFile(p)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("source changed")
				}
			}
		})
	}
}

func TestReviewInitializerProducesStartupCompatibleProfile(t *testing.T) {
	f := newInitFixture(t)
	if got := initialize(f.o); got != "created" {
		t.Fatal("initialize", got)
	}
	if err := lanstore.PrepareProfileDirectory(f.c.StateDirectory, lanconfig.TLS); err != nil {
		t.Fatal("normal startup profile admission failed", err)
	}
	profile := filepath.Join(f.c.StateDirectory, "profile")
	raw, err := os.ReadFile(profile)
	if err != nil || !bytes.Equal(raw, []byte("tracebolt.lan-state.v1\ntls\n")) {
		t.Fatal("missing exact TLS state binding")
	}
}

func TestReviewInitializerRejectsIncompatibleExistingProfile(t *testing.T) {
	f := newInitFixture(t)
	if err := lanstore.PrepareProfileDirectory(f.c.StateDirectory, lanconfig.HTTPTest); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(f.c.StateDirectory, "profile")
	before, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := initialize(f.o); got != "profile_state" {
		t.Fatal("incompatible profile admitted", got)
	}
	assertAbsent(t, f.paths()...)
	after, err := os.ReadFile(profile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("incompatible profile changed")
	}
	entries, err := os.ReadDir(f.c.StateDirectory)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected state mutated")
	}
}

func TestInitializePreservesExistingTLSProfile(t *testing.T) {
	f := newInitFixture(t)
	if err := lanstore.PrepareProfileDirectory(f.c.StateDirectory, lanconfig.TLS); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(f.c.StateDirectory, "profile")
	before, err := os.Stat(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := initialize(f.o); got != "created" {
		t.Fatal("compatible profile rejected", got)
	}
	after, err := os.Stat(profile)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("existing profile replaced")
	}
	if err := lanstore.PrepareProfileDirectory(f.c.StateDirectory, lanconfig.TLS); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeRejectsUnmarkedNonemptyAndMalformedProfile(t *testing.T) {
	for _, name := range []string{"unmarked-state", "profile"} {
		t.Run(name, func(t *testing.T) {
			f := newInitFixture(t)
			path := filepath.Join(f.c.StateDirectory, name)
			before := []byte("synthetic existing state must not be adopted")
			writeFixture(t, path, before)
			if got := initialize(f.o); got != "profile_state" {
				t.Fatal("invalid existing state admitted", got)
			}
			assertAbsent(t, f.paths()...)
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("existing state changed")
			}
			entries, err := os.ReadDir(f.c.StateDirectory)
			if err != nil || len(entries) != 1 {
				t.Fatal("failed profile admission mutated state")
			}
		})
	}
}
