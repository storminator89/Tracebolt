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

func completeArguments(apply bool) []string {
	args := inventoryArguments(apply)
	for i, value := range args {
		if value == inventoryProfileName {
			args[i] = completeProfileName
		}
	}
	return args
}
func completeFixtures(t *testing.T) []materialFile {
	t.Helper()
	password := fixturePassword()
	defer clear(password)
	files, e := generate(completeSetup, "192.168.1.50", password, rand.New(rand.NewSource(221)), fixtureTime())
	if e != nil {
		t.Fatal("synthetic complete material failed")
	}
	t.Cleanup(func() { clearFiles(files) })
	return files
}

func TestCompletePlanHasNoEffectsAndNamesScope(t *testing.T) {
	var out bytes.Buffer
	if run(context.Background(), completeArguments(false), &out, dependencies{}) != 0 {
		t.Fatal("complete plan accessed effectful dependencies")
	}
	for _, want := range []string{completeProfileName, completeOutputDirectory, "http://192.168.1.50:8787", "http://192.168.1.50:8788", "complete supported dpkg", "paginated", "not all software", "Unsupported software managers remain unknown", "sensitive", "HTTP exposes", "Quotas", "never a prefix labeled complete", "Current and previous", "original observation ages", "24-hour visibility", "persist after visibility expiry", "No AI export", "No CVE or update guarantees", "retained unused", "fresh state volume", "fresh endpoint identity", "active/failed/enablement", "locally observed TCP listeners", "UDP-bound sockets", "numeric local/remote addresses and ports", "PID/name attribution where permitted", "explicitly unknown", "Private network topology", "No network scans", "firewall/namespace/global privilege changes", "raw logs", "command lines", "environment", "usernames", "payloads", "DNS queries", "not collector/runtime availability"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("complete plan omitted required scope boundary")
		}
	}
	if strings.Contains(out.String(), "$argon2id$") || strings.Contains(out.String(), ":8789") || strings.Contains(out.String(), ":8790") {
		t.Fatal("complete plan leaked material or changed ports")
	}
}

func TestCompleteAcknowledgementAndUnknownSelectorsFailBeforeEffects(t *testing.T) {
	for _, selectors := range [][]string{
		{"--collection-profile", completeProfileName},
		{"--collection-profile", completeProfileName, "--ack-managed-metadata=false"},
		{"--collection-profile", "managed-operations-v4", "--ack-managed-metadata"},
		{"--collection-profile", completeProfileName, "--ack-managed-metadata", "--output-directory", "/etc/unapproved"},
	} {
		for _, apply := range []bool{false, true} {
			args := append([]string{"--lan-ip", "192.168.1.50", "--ack-disposable-http-test"}, selectors...)
			if apply {
				args = append(args, "--apply")
			}
			var out bytes.Buffer
			if run(context.Background(), args, &out, dependencies{}) == 0 || !strings.HasPrefix(out.String(), "HTTP-test setup failed:") {
				t.Fatal("inconsistent selector reached plan or effects")
			}
		}
	}
	var out bytes.Buffer
	args := []string{"--lan-ip", "192.168.1.50", "--collection-profile", completeProfileName, "--ack-managed-metadata", "--apply"}
	if run(context.Background(), args, &out, dependencies{}) == 0 || !strings.Contains(out.String(), "disposable HTTP acknowledgement required") {
		t.Fatal("complete metadata acknowledgement bypassed HTTP acknowledgement")
	}
}

func TestCompleteMaterialLoadsExactProfileWithoutRelabelingOlderProfiles(t *testing.T) {
	files := completeFixtures(t)
	basic := fixtureFiles(t)
	v2 := inventoryFixtures(t)
	var config, oldBasic, oldV2 enrollmentconfig.Config
	if json.Unmarshal(files[2].data, &config) != nil || json.Unmarshal(basic[2].data, &oldBasic) != nil || json.Unmarshal(v2[2].data, &oldV2) != nil {
		t.Fatal("synthetic enrollment JSON invalid")
	}
	if config.CollectionProfile != completeProfileName || config.BootstrapServerCAFile != "" || oldBasic.CollectionProfile != "" || bytes.Contains(basic[2].data, []byte("collectionProfile")) || oldV2.CollectionProfile != inventoryProfileName {
		t.Fatal("collection profiles were relabeled")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(files[2].data, &fields) != nil || len(fields) != 9 {
		t.Fatal("complete enrollment has unexpected schema fields")
	}
	for _, old := range []enrollmentconfig.Config{oldBasic, oldV2} {
		if config.InstanceID == old.InstanceID || config.ExpectedIssuerFingerprint == old.ExpectedIssuerFingerprint {
			t.Fatal("complete instance reused older identity")
		}
	}
	for _, old := range [][]materialFile{basic, v2} {
		if bytes.Equal(files[1].data, old[1].data) || bytes.Equal(files[4].data, old[4].data) {
			t.Fatal("complete instance reused older verifier or issuer key")
		}
	}
	var lan lanconfig.Config
	if json.Unmarshal(files[0].data, &lan) != nil || lan.OperatorOrigin != "http://192.168.1.50:8787" || lan.AgentOrigin != "http://192.168.1.50:8788" || lan.OperatorListen != "0.0.0.0:8787" || lan.AgentListen != "0.0.0.0:8788" {
		t.Fatal("complete fixed origins/listeners changed")
	}
	if lan.AgentClientCAFile != "/run/tracebolt/client-issuer.pem" || lan.OperatorAuthFile != "/run/tracebolt/operator-auth.json" || lan.StateDirectory != "/data/state" || lan.WebDirectory != "/tracebolt/web" {
		t.Fatal("complete container paths changed")
	}
	dir, parent := temporaryParent(t)
	if publish(completeSetup, context.Background(), parent, files, os.Geteuid(), os.Getegid()) != nil {
		t.Fatal("synthetic complete publication failed")
	}
	dest := filepath.Join(dir, completeOutputName)
	info, e := os.Stat(dest)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("complete directory protection changed")
	}
	for _, file := range files {
		info, e := os.Lstat(filepath.Join(dest, file.name))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("complete file protection changed")
		}
	}
	// Only temporary synthetic fixture references are remapped for existing loaders.
	lan.AgentClientCAFile = filepath.Join(dest, "client-issuer.pem")
	lan.OperatorAuthFile = filepath.Join(dest, "operator-auth.json")
	config.IssuerCertificateFile = lan.AgentClientCAFile
	config.IssuerPrivateKeyFile = filepath.Join(dest, "client-issuer.key")
	config.IssuerRootFile = filepath.Join(dest, "client-root.pem")
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
	write("enrollment.json", config)
	loaded, e := lanconfig.Load(filepath.Join(dest, "http-test.json"))
	if e != nil {
		t.Fatal("LAN loader rejected complete fixture")
	}
	if _, e = operatorauth.New(operatorauth.Config{PasswordHash: loaded.PasswordHash}); e != nil {
		t.Fatal("auth loader rejected complete fixture")
	}
	enrolled, e := enrollmentconfig.Load(filepath.Join(dest, "enrollment.json"), loaded, fixtureTime())
	if e != nil || !enrolled.ValidFor(lan) || enrolled.StoreConfig().Binding.CollectionProfile != completeProfileName || enrolled.StoreConfig().Binding.InstanceID != config.InstanceID {
		t.Fatal("enrollment loader rejected exact complete binding")
	}
}

func TestCompleteTargetAndStageRefusals(t *testing.T) {
	files := completeFixtures(t)
	for _, kind := range []string{"file", "directory", "symlink", "stale"} {
		t.Run(kind, func(t *testing.T) {
			dir, parent := temporaryParent(t)
			target := filepath.Join(dir, completeOutputName)
			switch kind {
			case "file":
				os.WriteFile(target, []byte("preserve"), 0600)
			case "directory":
				os.Mkdir(target, 0700)
			case "symlink":
				os.Symlink("missing", target)
			case "stale":
				os.Mkdir(filepath.Join(dir, completeStagePrefix+"interrupted"), 0700)
			}
			before, _ := os.ReadDir(dir)
			if outputAbsent(completeSetup, parent) == nil || publish(completeSetup, context.Background(), parent, files, os.Geteuid(), os.Getegid()) == nil {
				t.Fatal("selected complete output accepted existing material")
			}
			after, _ := os.ReadDir(dir)
			if len(before) != len(after) {
				t.Fatal("selected complete output reset existing material")
			}
			var out bytes.Buffer
			if run(context.Background(), completeArguments(true), &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }}) == 0 || !strings.Contains(out.String(), "protected parent or existing output") {
				t.Fatal("existing complete output reached password prompt")
			}
		})
	}
}

func TestCompleteInjectedApplyPreservesBothOlderSetups(t *testing.T) {
	dir, parent := temporaryParent(t)
	older := map[string]os.FileInfo{}
	for _, name := range []string{outputName, inventoryOutputName} {
		path := filepath.Join(dir, name)
		if os.Mkdir(path, 0700) != nil || os.WriteFile(filepath.Join(path, "sentinel"), []byte("retained-unused"), 0600) != nil || os.Chmod(path, 0000) != nil {
			t.Fatal("legacy synthetic sentinel creation failed")
		}
		t.Cleanup(func() { os.Chmod(path, 0700) })
		older[path], _ = os.Lstat(path)
	}
	var out bytes.Buffer
	password := fixturePassword()
	code := run(context.Background(), completeArguments(true), &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }, prompt: func(context.Context) ([]byte, error) {
		if !strings.Contains(out.String(), completeNotice) {
			t.Fatal("complete scope plan did not precede prompt")
		}
		return password, nil
	}, random: rand.New(rand.NewSource(332)), now: fixtureTime, uid: os.Geteuid(), gid: os.Getegid()})
	if code != 0 || !strings.Contains(out.String(), completeOutputDirectory+"/http-test.json") || !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("complete fixture apply failed or did not clear password")
	}
	for path, before := range older {
		after, e := os.Lstat(path)
		if e != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0000 {
			t.Fatal("complete setup changed an older directory")
		}
		if os.Chmod(path, 0700) != nil {
			t.Fatal("restore synthetic sentinel access")
		}
		raw, e := os.ReadFile(filepath.Join(path, "sentinel"))
		if e != nil || string(raw) != "retained-unused" {
			t.Fatal("complete setup modified old material")
		}
	}
}
