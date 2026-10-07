package nativeapt

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"localrmm/internal/actionpermit"
	"localrmm/internal/packageplan"
)

const fixtureID = "update_11111111111111111111111111111111"

// These are invented comparison fixtures, never native transaction evidence.
func fixture(t *testing.T) (Prepared, Binding, []byte, []packageplan.ObservedArchive) {
	t.Helper()
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := packageplan.Decode(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	paths, _ := JobPaths(fixtureID)
	hook, e := os.ReadFile("../packageplan/testdata/single.hook")
	if e != nil {
		t.Fatal(e)
	}
	hook = bytes.ReplaceAll(hook, []byte("/var/cache/apt/archives"), []byte(paths.Archives))
	d := actionpermit.Digest([]byte("fixture-only"))
	a := p.Packages[0].Archive
	b := Prepared{Version: BundleVersion, UpdateID: fixtureID, APTVersion: SupportedAPTVersion, MetadataRefreshedAt: p.Evidence.MetadataRefreshedAt, InventoryAt: p.Evidence.InventoryAt, InventoryDigest: p.Evidence.DpkgStateDigest, DpkgStateDigest: p.Evidence.DpkgStateDigest, HoldsDigest: p.Evidence.HoldsDigest, SourceSnapshotDigest: d, HostConfigDigest: d, APTConfigDigest: actionpermit.Digest(ConfigBytes(paths, fixtureID)), Packages: p.Packages, Sources: []Source{{a.SourceIdentityDigest, "Debian", "stable", "main"}}, Archives: []StagedArchive{{paths.Archives + "/sample-bin_1.0-2_amd64.deb", a.SHA256, a.Size}}}
	bind := Binding{p.EndpointID, p.IncarnationDigest, p.RootPolicyDigest, p.Evidence.HookPolicyDigest, p.CreatedAt, p.ExpiresAt}
	return b, bind, hook, []packageplan.ObservedArchive{{Path: b.Archives[0].Path, SHA256: a.SHA256, Size: a.Size}}
}
func TestFixedInvocationAndNoModeFlag(t *testing.T) {
	ss := []ExactSelection{{"aa", "amd64", "1:2.0-1"}, {"aa-extra", "amd64", "2.0-1"}}
	a, e := BuildInvocation(fixtureID, ss)
	if e != nil {
		t.Fatal(e)
	}
	b, e := BuildInvocation(fixtureID, ss)
	if e != nil {
		t.Fatal(e)
	}
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if !bytes.Equal(aa, bb) {
		t.Fatal("capture/execute differ")
	}
	if a.Executable != "/usr/bin/apt-get" || strings.Join(a.Args, " ") != "--assume-yes --no-download --only-upgrade --no-remove install aa:amd64=1:2.0-1 aa-extra:amd64=2.0-1" {
		t.Fatal(a)
	}
	for _, bad := range []string{"--force-confdef", "--force-yes", "AllowUnauthenticated \"true\"", "Pre-Invoke", "capture", "execute", "$JOB", "$ID"} {
		if bytes.Contains(a.Config, []byte(bad)) {
			t.Fatalf("unsafe config %s", bad)
		}
	}
	if strings.Count(string(a.Config), "DPkg::Pre-Install-Pkgs {") != 1 || !bytes.Contains(a.Config, []byte(GuardExecutable+" "+fixtureID)) {
		t.Fatal("missing single guard")
	}
	paths, _ := JobPaths(fixtureID)
	if !bytes.Equal(a.Config, ConfigBytes(Paths{Directory: "/attacker"}, fixtureID)) || paths.Directory != JobRoot+"/"+fixtureID {
		t.Fatal("request path injected")
	}
	t.Setenv("APT_CONFIG", "/untrusted")
	t.Setenv("LD_PRELOAD", "/untrusted")
	if strings.Contains(strings.Join(Environment(fixtureID), " "), "untrusted") {
		t.Fatal("environment inherited")
	}
}
func TestSelectionAndInvocationRejectInjection(t *testing.T) {
	for _, id := range []string{"", "../update_x", fixtureID + "/x", "update_" + strings.Repeat("0", 32)} {
		if _, e := JobPaths(id); e == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	for _, ss := range [][]Selection{nil, {{"aa", "all"}}, {{"aa", "i386"}}, {{"-option", "amd64"}}, {{"aa;sh", "amd64"}}, {{"aa", "amd64"}, {"aa", "amd64"}}, {{"bb", "amd64"}, {"aa", "amd64"}}} {
		if _, e := SelectionBytes(ss); e == nil {
			t.Fatalf("accepted %+v", ss)
		}
	}
	for _, v := range []string{"", "2.0\n-oFoo=bar", "2.0 --allow-remove-essential"} {
		if _, e := BuildInvocation(fixtureID, []ExactSelection{{"aa", "amd64", v}}); e == nil {
			t.Fatalf("accepted version %q", v)
		}
	}
}
func TestPreparedCanonicalAndEvidenceValidation(t *testing.T) {
	b, _, _, _ := fixture(t)
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodePrepared(context.Background(), raw, fixtureID); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), '\n'), bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":0,"version":`), 1), bytes.Replace(raw, []byte(`"version":`), []byte(`"updateId":"wrong","version":`), 1), bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1)} {
		if _, e := DecodePrepared(context.Background(), bad, fixtureID); e == nil {
			t.Fatal("accepted noncanonical bundle")
		}
	}
	for name, mutate := range map[string]func(*Prepared){"other tool": func(b *Prepared) { b.APTVersion = "3.1" }, "invented config": func(b *Prepared) { b.APTConfigDigest = actionpermit.Digest([]byte("different")) }, "path escape": func(b *Prepared) { b.Archives[0].Path = "/tmp/foreign.deb" }, "archive digest": func(b *Prepared) { b.Archives[0].SHA256 = actionpermit.Digest([]byte("changed")) }, "missing source": func(b *Prepared) { b.Sources = nil }, "source label control": func(b *Prepared) { b.Sources[0].Label = "forged\nlabel" }, "expired refresh": func(b *Prepared) { b.InventoryAt = b.MetadataRefreshedAt + 301 }, "empty packages": func(b *Prepared) { b.Packages = nil }} {
		t.Run(name, func(t *testing.T) {
			var c Prepared
			_ = json.Unmarshal(raw, &c)
			mutate(&c)
			if c.Validate(context.Background(), fixtureID) == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}
func TestCaptureDerivesOnlyObservedConfigAndMatchesActualArchives(t *testing.T) {
	b, bind, hook, archives := fixture(t)
	p, e := FinalizeCapture(context.Background(), b, bind, hook, archives)
	if e != nil {
		t.Fatal(e)
	}
	parsed, _ := packageplan.ParseHook(context.Background(), hook)
	if p.Evidence.ConfigDigest != parsed.ConfigDigest {
		t.Fatal("invented config digest")
	}
	if _, e := FinalizeCapture(context.Background(), b, bind, nil, archives); e == nil {
		t.Fatal("accepted absent actual capture")
	}
	archives[0].SHA256 = actionpermit.Digest([]byte("changed"))
	if _, e := FinalizeCapture(context.Background(), b, bind, hook, archives); e == nil {
		t.Fatal("accepted changed archive")
	}
	_, _, _, archives = fixture(t)
	bind.CreatedAt = b.InventoryAt + 61
	bind.ExpiresAt = bind.CreatedAt + 60
	if _, e := FinalizeCapture(context.Background(), b, bind, hook, archives); e == nil {
		t.Fatal("refreshed stale inventory timestamp")
	}
}
func TestHostConfigDigestCanonicalAndSensitiveToBytes(t *testing.T) {
	a := []SnapshotFile{{"etc/apt/apt.conf.d/b", []byte("second")}, {"etc/apt/apt.conf", []byte("first")}}
	d, e := ConfigSnapshotDigest(a)
	if e != nil {
		t.Fatal(e)
	}
	b := []SnapshotFile{a[1], a[0]}
	d2, e := ConfigSnapshotDigest(b)
	if e != nil || d2 != d {
		t.Fatal("nondeterministic")
	}
	b[0].Contents = []byte("changed")
	d2, _ = ConfigSnapshotDigest(b)
	if d == d2 {
		t.Fatal("unbound bytes")
	}
	for _, n := range []string{"../escape", "/absolute", "a\x00b", "a//b"} {
		if _, e := ConfigSnapshotDigest([]SnapshotFile{{n, nil}}); e == nil {
			t.Fatalf("accepted %q", n)
		}
	}
	if _, e := ConfigSnapshotDigest([]SnapshotFile{{"a", nil}, {"a", nil}}); e == nil {
		t.Fatal("duplicate")
	}
}

func TestDPKGConfigurationHasNoForcePathOrHookEscape(t *testing.T) {
	for _, raw := range []string{"", "# comment\nno-debsig\nlog /var/log/dpkg.log\n", " \t# comment\n  no-debsig \r\n"} {
		if ValidateDPKGConfig([]byte(raw)) != nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"force-confnew\n", "force-confdef\n", "force-unsafe-io\n", "root=/other\n", "admindir=/other\n", "instdir=/other\n", "pre-invoke=anything\n", "log /other\n", "no-debsig #comment\n"} {
		if ValidateDPKGConfig([]byte(raw)) == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestSourceSnapshotBindsEveryByteAndField(t *testing.T) {
	d, e := SourceSnapshotDigest([]byte("source\n"), nil, []byte("key\x00bytes"))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range [][3][]byte{{[]byte("different\n"), nil, []byte("key\x00bytes")}, {[]byte("source\n"), []byte("pin"), []byte("key\x00bytes")}, {[]byte("source\n"), nil, []byte("key\x00other")}} {
		got, e := SourceSnapshotDigest(v[0], v[1], v[2])
		if e != nil || got == d {
			t.Fatal("unbound field")
		}
	}
	if _, e := SourceSnapshotDigest(nil, nil, []byte("key")); e == nil {
		t.Fatal("missing source")
	}
	if _, e := SourceSnapshotDigest([]byte("source"), nil, nil); e == nil {
		t.Fatal("missing key")
	}
}
