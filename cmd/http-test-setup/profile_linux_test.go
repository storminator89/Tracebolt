//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
)

func inventoryArguments(apply bool) []string {
	args := []string{"--lan-ip", "192.168.1.50", "--collection-profile", inventoryProfileName, "--ack-managed-metadata", "--ack-disposable-http-test"}
	if apply {
		args = append(args, "--apply")
	}
	return args
}
func inventoryFixtures(t *testing.T) []materialFile {
	t.Helper()
	password := fixturePassword()
	defer clear(password)
	files, e := generate(inventorySetup, "192.168.1.50", password, rand.New(rand.NewSource(91)), fixtureTime())
	if e != nil {
		t.Fatal("synthetic managed material failed")
	}
	t.Cleanup(func() { clearFiles(files) })
	return files
}

func TestExplicitProfilePlansAreNonMutating(t *testing.T) {
	var basic, explicitBasic, inventory bytes.Buffer
	if run(context.Background(), []string{"--lan-ip", "192.168.1.50"}, &basic, dependencies{}) != 0 || run(context.Background(), []string{"--lan-ip", "192.168.1.50", "--collection-profile", basicProfileName}, &explicitBasic, dependencies{}) != 0 {
		t.Fatal("basic plan failed")
	}
	if basic.String() != explicitBasic.String() || strings.Contains(basic.String(), "managed-operations") || strings.Contains(basic.String(), inventoryOutputDirectory) {
		t.Fatal("basic default changed")
	}
	if run(context.Background(), inventoryArguments(false), &inventory, dependencies{}) != 0 {
		t.Fatal("managed plan required effectful dependencies")
	}
	for _, expected := range []string{inventoryOutputDirectory, "http://192.168.1.50:8787", "http://192.168.1.50:8788", inventoryProfileName, "volume/mount", "interface", "service", "process", "package", "source versions", "source mappings", "OS release", "event", "sensitive", "HTTP exposes", "retained unused", "fresh state volume", "stop the old test container"} {
		if !strings.Contains(inventory.String(), expected) {
			t.Fatal("managed plan omitted a fixed boundary")
		}
	}
	if strings.Contains(inventory.String(), ":8789") || strings.Contains(inventory.String(), ":8790") || strings.Contains(inventory.String(), "$argon2id$") {
		t.Fatal("managed plan has wrong ports or private material")
	}
}

func TestInconsistentProfileSelectorsFailBeforeEffects(t *testing.T) {
	invalid := [][]string{
		{"--collection-profile", inventoryProfileName},
		{"--collection-profile", inventoryProfileName, "--ack-managed-metadata=false"},
		{"--ack-managed-metadata"},
		{"--collection-profile", basicProfileName, "--ack-managed-metadata"},
		{"--collection-profile", "managed-operations-v1", "--ack-managed-metadata"},
		{"--collection-profile", "secret-unknown-profile", "--ack-managed-metadata"},
		{"--collection-profile", "", "--ack-managed-metadata"},
		{"--output-directory", "/etc/not-allowed"},
		{"--operator-port", "8789"},
	}
	for _, selector := range invalid {
		for _, apply := range []bool{false, true} {
			args := append([]string{"--lan-ip", "192.168.1.50", "--ack-disposable-http-test"}, selector...)
			if apply {
				args = append(args, "--apply")
			}
			var out bytes.Buffer
			// Nil root/prompt/parent/random dependencies make an accidental effect fail.
			if run(context.Background(), args, &out, dependencies{}) == 0 || !strings.HasPrefix(out.String(), "HTTP-test setup failed:") || strings.Contains(out.String(), "secret-unknown-profile") {
				t.Fatal("invalid selector reached a plan or leaked its value")
			}
		}
	}
	// Metadata consent cannot replace the separate plaintext apply acknowledgement.
	var out bytes.Buffer
	args := []string{"--lan-ip", "192.168.1.50", "--collection-profile", inventoryProfileName, "--ack-managed-metadata", "--apply"}
	if run(context.Background(), args, &out, dependencies{}) == 0 || !strings.Contains(out.String(), "disposable HTTP acknowledgement required") {
		t.Fatal("HTTP acknowledgement bypassed")
	}
}

func TestManagedMaterialLoadsWithExactFreshBinding(t *testing.T) {
	files := inventoryFixtures(t)
	basic := fixtureFiles(t)
	var cfg enrollmentconfig.Config
	if json.Unmarshal(files[2].data, &cfg) != nil || cfg.CollectionProfile != inventoryProfileName || cfg.BootstrapServerCAFile != "" {
		t.Fatal("managed enrollment shape changed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(files[2].data, &fields) != nil || len(fields) != 9 {
		t.Fatal("unexpected managed enrollment fields")
	}
	var old enrollmentconfig.Config
	if json.Unmarshal(basic[2].data, &old) != nil || old.CollectionProfile != "" || bytes.Contains(basic[2].data, []byte("collectionProfile")) {
		t.Fatal("basic omission compatibility changed")
	}
	if cfg.InstanceID == old.InstanceID || cfg.ExpectedIssuerFingerprint == old.ExpectedIssuerFingerprint || bytes.Equal(files[1].data, basic[1].data) || bytes.Equal(files[4].data, basic[4].data) {
		t.Fatal("managed instance reused synthetic basic identity or auth")
	}
	var lan lanconfig.Config
	if json.Unmarshal(files[0].data, &lan) != nil || lan.OperatorOrigin != "http://192.168.1.50:8787" || lan.AgentOrigin != "http://192.168.1.50:8788" || lan.OperatorListen != "0.0.0.0:8787" || lan.AgentListen != "0.0.0.0:8788" {
		t.Fatal("managed fixed ports changed")
	}
	if lan.AgentClientCAFile != "/run/tracebolt/client-issuer.pem" || lan.OperatorAuthFile != "/run/tracebolt/operator-auth.json" || lan.StateDirectory != "/data/state" || lan.WebDirectory != "/tracebolt/web" {
		t.Fatal("managed container paths changed")
	}
	dir, parent := temporaryParent(t)
	if publish(inventorySetup, context.Background(), parent, files, os.Geteuid(), os.Getegid()) != nil {
		t.Fatal("synthetic managed publish failed")
	}
	dest := filepath.Join(dir, inventoryOutputName)
	info, e := os.Stat(dest)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("managed directory mode changed")
	}
	for _, f := range files {
		info, e := os.Lstat(filepath.Join(dest, f.name))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("managed private file protection changed")
		}
	}
	// Rewrite only synthetic temporary fixture references for the protected loaders.
	lan.AgentClientCAFile = filepath.Join(dest, "client-issuer.pem")
	lan.OperatorAuthFile = filepath.Join(dest, "operator-auth.json")
	cfg.IssuerCertificateFile = lan.AgentClientCAFile
	cfg.IssuerPrivateKeyFile = filepath.Join(dest, "client-issuer.key")
	cfg.IssuerRootFile = filepath.Join(dest, "client-root.pem")
	write := func(name string, v any) {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal("fixture encoding failed")
		}
		defer clear(raw)
		if os.WriteFile(filepath.Join(dest, name), raw, 0600) != nil {
			t.Fatal("fixture remapping failed")
		}
	}
	write("http-test.json", lan)
	write("enrollment.json", cfg)
	loaded, e := lanconfig.Load(filepath.Join(dest, "http-test.json"))
	if e != nil {
		t.Fatal("LAN loader refused managed fixture")
	}
	if _, e = operatorauth.New(operatorauth.Config{PasswordHash: loaded.PasswordHash}); e != nil {
		t.Fatal("auth loader refused managed fixture")
	}
	enrolled, e := enrollmentconfig.Load(filepath.Join(dest, "enrollment.json"), loaded, fixtureTime())
	if e != nil || !enrolled.ValidFor(lan) || enrolled.StoreConfig().Binding.CollectionProfile != inventoryProfileName || enrolled.StoreConfig().Binding.InstanceID != cfg.InstanceID {
		t.Fatal("enrollment loader changed selected managed binding")
	}
}

func TestBothProfilesRefuseSelectedExistingAndStaleOutputs(t *testing.T) {
	files := fixtureFiles(t)
	for _, profile := range []setupProfile{basicSetup, inventorySetup} {
		for _, kind := range []string{"file", "directory", "symlink", "stale"} {
			t.Run(profileLabel(profile)+"/"+kind, func(t *testing.T) {
				dir, parent := temporaryParent(t)
				_, name, staging, _ := profile.paths()
				target := filepath.Join(dir, name)
				switch kind {
				case "file":
					os.WriteFile(target, []byte("preserve"), 0600)
				case "directory":
					os.Mkdir(target, 0700)
				case "symlink":
					os.Symlink("missing", target)
				case "stale":
					os.Mkdir(filepath.Join(dir, staging+"interrupted"), 0700)
				}
				before, _ := os.ReadDir(dir)
				if outputAbsent(profile, parent) == nil || publish(profile, context.Background(), parent, files, os.Geteuid(), os.Getegid()) == nil {
					t.Fatal("selected existing output accepted")
				}
				after, _ := os.ReadDir(dir)
				if len(before) != len(after) {
					t.Fatal("selected output was reset")
				}
				args := inventoryArguments(true)
				if profile == basicSetup {
					args = []string{"--lan-ip", "192.168.1.50", "--ack-disposable-http-test", "--apply"}
				}
				var out bytes.Buffer
				if run(context.Background(), args, &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }}) == 0 || !strings.Contains(out.String(), "protected parent or existing output") {
					t.Fatal("existing output reached password prompt")
				}
			})
		}
	}
}
func profileLabel(p setupProfile) string {
	if p == inventorySetup {
		return "inventory"
	}
	return "basic"
}

func TestManagedApplyLeavesBasicMaterialUntouched(t *testing.T) {
	dir, parent := temporaryParent(t)
	old := filepath.Join(dir, outputName)
	if os.Mkdir(old, 0700) != nil || os.WriteFile(filepath.Join(old, "sentinel"), []byte("old-material-retained"), 0600) != nil || os.Chmod(old, 0000) != nil {
		t.Fatal("create protected legacy sentinel")
	}
	t.Cleanup(func() { os.Chmod(old, 0700) })
	// No old material can be read; selected setup only checks names in the parent.
	before, _ := os.Lstat(old)
	var out bytes.Buffer
	password := fixturePassword()
	code := run(context.Background(), inventoryArguments(true), &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }, prompt: func(context.Context) ([]byte, error) {
		if !strings.Contains(out.String(), inventoryNotice) {
			t.Fatal("metadata plan did not precede prompt")
		}
		return password, nil
	}, random: rand.New(rand.NewSource(127)), now: fixtureTime, uid: os.Geteuid(), gid: os.Getegid()})
	after, _ := os.Lstat(old)
	if code != 0 || !os.SameFile(before, after) || after.Mode().Perm() != 0000 || !strings.Contains(out.String(), inventoryOutputDirectory+"/http-test.json") {
		t.Fatal("managed apply affected legacy target or wrong result")
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("managed password buffer not cleared")
	}
	if os.Chmod(old, 0700) != nil {
		t.Fatal("restore synthetic sentinel access")
	}
	got, e := os.ReadFile(filepath.Join(old, "sentinel"))
	if e != nil || string(got) != "old-material-retained" {
		t.Fatal("legacy material changed")
	}
}
