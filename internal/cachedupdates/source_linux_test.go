//go:build linux

package cachedupdates

import (
	"context"
	"strings"
	"testing"
)

func TestFixedNativeCommandsHaveNoRefreshOrWritableCache(t *testing.T) {
	joined := strings.Join(policyOptions, "\n")
	for _, required := range []string{"Dir::Cache::pkgcache=", "Dir::Cache::srcpkgcache=", "Dir::State::status=/var/lib/dpkg/status", "Dir::State::lists=/var/lib/apt/lists", "policy"} {
		if !strings.Contains(joined, required) {
			t.Fatal(required)
		}
	}
	for _, bad := range []string{"update", "install", "upgrade", "Pre-Invoke", "Post-Invoke"} {
		for _, arg := range policyOptions {
			if arg == bad {
				t.Fatal("unsafe operation", arg)
			}
		}
	}
	if _, e := runCommand(context.Background(), "/bin/sh", []string{"-c", "exit 0"}); e == nil {
		t.Fatal("arbitrary executable accepted")
	}
}
func TestOnlyPackageIndexNamesContributeModificationAge(t *testing.T) {
	for _, name := range []string{"example_dists_trixie_main_binary-amd64_Packages", "example_Packages.lz4", "example_Packages.gz", "example_Packages.xz"} {
		if !packageIndex(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"lock", "partial", "example_InRelease", "example_Release", "example_Translation-en", "update-success-stamp"} {
		if packageIndex(name) {
			t.Fatal(name)
		}
	}
}
func TestFixedPolicyRejectsPackageArgumentInjectionBeforeCommand(t *testing.T) {
	s := &linuxSource{}
	for _, p := range []installedPackage{{"--config-file", "amd64", "1.0", false}, {"pkg;touch /tmp/x", "amd64", "1.0", false}, {"valid-pkg", "amd64 --foo", "1.0", false}} {
		if _, e := s.policy(context.Background(), []installedPackage{p}); e == nil {
			t.Fatal("unsafe argv accepted")
		}
	}
}
func TestSnapshotCountOverflowRejected(t *testing.T) {
	s := collectFixture(t, fixture("debian"))
	max, one := uint32(4294967295), uint32(3)
	s.CheckedCount = &max
	s.UnknownCount = &one
	if Validate(s) == nil {
		t.Fatal("wrapped counters accepted")
	}
}

func TestReleaseMetadataIsPinnedSeparatelyFromAge(t *testing.T) {
	for _, name := range []string{"mirror_dists_trixie_InRelease", "mirror_dists_noble_Release", "mirror_dists_noble_Release.gpg"} {
		if !releaseIndex(name) || packageIndex(name) {
			t.Fatal(name)
		}
	}
	if releaseIndex("lock") {
		t.Fatal("lock is not release metadata")
	}
}

func TestNestedAPTConfigDirectivesFailClosed(t *testing.T) {
	for _, raw := range []string{`#include "/outside/config";`, `#clear APT;`, `// #include mention`} {
		if !unsupportedConfigDirective([]byte(raw)) {
			t.Fatal(raw)
		}
	}
	if unsupportedConfigDirective([]byte("# ordinary comment\nAPT::Default-Release \"noble\";")) {
		t.Fatal("ordinary native policy rejected")
	}
}

func TestAPTDirectoryRedirectionFailsClosed(t *testing.T) {
	for _, raw := range []string{`Dir::Etc::main "/outside/policy";`, `Dir { Etc { main "/outside/policy"; }; };`, `RootDir "/alternate";`, `dir::etc::parts "/outside";`, `Dir::Cache::pkgcache "";`, `// Dir::Etc comment`, `D/**/ir::Etc::main "/outside/policy";`, `#in/**/clude "/outside/policy";`, `/* harmless block comment */`} {
		if !unsupportedConfigDirective([]byte(raw)) {
			t.Fatal(raw)
		}
	}
	if unsupportedConfigDirective([]byte(`APT::Default-Release "noble";`)) {
		t.Fatal("ordinary native policy rejected")
	}
}
