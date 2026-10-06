//go:build linux

package cachedupdates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Debian installer template (the four lines emitted as 00CDMountPoint):
// https://sources.debian.org/src/base-installer/1.226/library.sh/
const debianCDMountPoint = `Acquire::cdrom {
  mount "/media/cdrom";
};
Dir::Media::MountPath "/media/cdrom";
`

// Debian trixie apt-listchanges 4.8, debian/apt.conf (20listchanges):
// https://sources.debian.org/src/apt-listchanges/4.8/debian/apt.conf/
const debianListChanges = `DPkg::Pre-Install-Pkgs { "/usr/bin/apt-listchanges --apt || test $? -lt 10"; };
DPkg::Tools::Options::/usr/bin/apt-listchanges::Version "2";
DPkg::Tools::Options::/usr/bin/apt-listchanges::InfoFD "20";
Dir::Etc::apt-listchanges-main "listchanges.conf";
Dir::Etc::apt-listchanges-parts "listchanges.conf.d";
`

func TestDebianNetinstAPTDefaults(t *testing.T) {
	for name, raw := range map[string]string{"00CDMountPoint": debianCDMountPoint, "20listchanges": debianListChanges} {
		t.Run(name, func(t *testing.T) {
			if !configDirectoryPattern.MatchString(raw) {
				t.Fatal("fixture does not reproduce the rc.2 blanket directory gate")
			}
			before := []byte(raw)
			if unsupportedConfigDirective(before) {
				t.Fatal("stock Debian default rejected")
			}
			if string(before) != raw {
				t.Fatal("source configuration was modified")
			}
		})
	}
	for _, raw := range []string{
		debianCDMountPoint + debianListChanges,
		"// ordinary comment\n" + debianCDMountPoint + "# ordinary comment\n",
		strings.ReplaceAll(debianCDMountPoint, "Dir::Media", "dIR::mEDIA"),
		"Dir::Etc::apt-listchanges-main\n\t\"listchanges.conf\" \t;\n",
		"APT::Default-Release \"trixie\"; " + debianListChanges,
	} {
		if unsupportedConfigDirective([]byte(raw)) {
			t.Fatalf("compatible flat default rejected: %q", raw)
		}
	}
}

func TestDebianDefaultsNeverPermitAPTPathRedirection(t *testing.T) {
	for _, bad := range []string{
		`Dir "/outside";`, `RootDir "/outside";`, `Dir::Etc "/outside";`,
		`Dir::Etc::main "/outside";`, `Dir::Etc::parts "/outside";`,
		`Dir::Etc::sourcelist "/outside";`, `Dir::Etc::sourceparts "/outside";`,
		`Dir::Etc::preferences "/outside";`, `Dir::State::lists "/outside";`,
		`Dir::State::status "/outside";`, `Dir::Cache::pkgcache "";`,
		`Dir { Etc { main "/outside"; }; };`,
		`#include "/outside";`, `#clear Dir;`,
		`D/**/ir::Etc::main "/outside";`, `#in/**/clude "/outside";`,
		`/* harmless block comment */`, `// Dir::Etc comment`,
		`APT::Something "Dir::Etc::main";`,
	} {
		for _, raw := range []string{bad + "\n" + debianListChanges, debianListChanges + "\n" + bad} {
			if !unsupportedConfigDirective([]byte(raw)) {
				t.Fatalf("redirect or unsupported syntax bypassed gate: %q", raw)
			}
		}
	}
}

func TestDebianDefaultExceptionsRequireExactTopLevelScalarGrammar(t *testing.T) {
	for _, raw := range []string{
		`Dir::Media::MountPath "/different";`,
		`Dir::Etc::apt-listchanges-main "/outside";`,
		`Dir::Etc::apt-listchanges-parts "../outside";`,
		`Dir::Etc::apt-listchanges-main::main "listchanges.conf";`,
		`Dir::Etc::apt-listchanges-main-extra "listchanges.conf";`,
		`"Dir::Etc::apt-listchanges-main" "listchanges.conf";`,
		`Dir::Etc::apt-listchanges-main { "listchanges.conf"; };`,
		`APT { Dir::Etc::apt-listchanges-main "listchanges.conf"; };`,
		`Dir { Etc { apt-listchanges-main "listchanges.conf"; }; };`,
		`APT::Value "Dir::Etc::apt-listchanges-main listchanges.conf";`,
		`Dir::Etc::apt-listchanges-main listchanges.conf;`,
		`Dir::Etc::apt-listchanges-main "listchanges.conf"`,
		`Dir::Etc::apt-listchanges-main "listchanges.conf" "other";`,
		`Dir::Etc::apt-listchanges-main "listchanges.conf\";`,
		`Dir::Etc::apt-listchanges-main "listchanges.conf"; }`,
		`APT { "unfinished"; ` + debianListChanges,
		`APT { "missing scope semicolon"; } ` + debianListChanges,
		strings.Repeat("APT { ", 33) + strings.Repeat("}; ", 33) + debianListChanges,
	} {
		if !unsupportedConfigDirective([]byte(raw)) {
			t.Fatalf("unsupported default form accepted: %q", raw)
		}
	}
}

type debianConfigFixture struct {
	*fixtureSource
	source *linuxSource
	paths  []string
}

func (f debianConfigFixture) metadata(ctx context.Context) (time.Time, error) {
	for _, path := range f.paths {
		if e := f.source.checkPolicyConfig(path); e != nil {
			return time.Time{}, e
		}
	}
	return f.fixtureSource.metadata(ctx)
}

func TestCompleteDebianCaptureChecksRealFixtureConfigFiles(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		f := debianConfigFixture{fixtureSource: fixture("debian"), source: &linuxSource{paths: map[string]unix.Stat_t{}}}
		dir := t.TempDir()
		for name, raw := range map[string]string{"00CDMountPoint": debianCDMountPoint, "20listchanges": debianListChanges} {
			if rejected && name == "20listchanges" {
				raw += `Dir::Etc::main "/outside";`
			}
			path := filepath.Join(dir, name)
			if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
				t.Fatal(e)
			}
			var st unix.Stat_t
			if e := unix.Lstat(path, &st); e != nil {
				t.Fatal(e)
			}
			f.source.paths[path] = st
			f.paths = append(f.paths, path)
		}
		full, e := completeFixture(t, f)
		if rejected {
			if e == nil || full.Complete || full.Rows != nil || full.Snapshot.Reason != ReasonNotSupported || full.Snapshot.CandidateCount != nil {
				t.Fatal("redirect became complete or successful zero", e)
			}
			if strings.Contains(strings.Join(f.calls, ","), "policy") {
				t.Fatal("policy query occurred after rejected config")
			}
		} else if e != nil || !full.Complete || len(full.Rows) != 2 || full.Snapshot.Metadata.Refresh != "not_attempted" || !full.Snapshot.Metadata.OldestIndexModifiedAt.Equal(f.oldest) {
			t.Fatal("default config did not preserve cached-only complete capture", e)
		}
		for _, path := range f.paths {
			var after unix.Stat_t
			if e := unix.Lstat(path, &after); e != nil || !sameStat(f.source.paths[path], after) {
				t.Fatal("configuration file changed", e)
			}
		}
	}
}
