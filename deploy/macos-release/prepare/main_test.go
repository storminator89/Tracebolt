//go:build (darwin && !ios) || (linux && !android)

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fixtureMember struct {
	name  string
	bytes []byte
	kind  byte
	mode  int64
}

func fixtureMacho(arch, name string) []byte {
	b := make([]byte, 16+len(name))
	copy(b, []byte("\xcf\xfa\xed\xfe"))
	binary.LittleEndian.PutUint32(b[4:8], machoCPU(arch))
	binary.LittleEndian.PutUint32(b[12:16], 2)
	copy(b[16:], []byte(name))
	return b
}

func fixtureRoleInspector(t *testing.T) {
	t.Helper()
	old := inspectRole
	inspectRole = func(raw []byte, name, arch string) error {
		if !bytes.Equal(raw[16:], []byte(name)) {
			return errRejected
		}
		return nil
	}
	t.Cleanup(func() { inspectRole = old })
}

func fixtureArchive(t *testing.T, arch string, mutate func([]fixtureMember) []fixtureMember, mutateManifest func(map[string]any)) (string, string) {
	t.Helper()
	files := map[string][]byte{}
	for _, name := range memberNames {
		if name == "payload-manifest.json" {
			continue
		}
		if len(name) >= 4 && name[:4] == "bin/" {
			files[name] = fixtureMacho(arch, name)
		} else {
			files[name] = []byte("synthetic review fixture")
		}
	}
	assets := map[string]any{}
	for name, data := range files {
		h := sha256.Sum256(data)
		assets[name] = map[string]any{"size": len(data), "sha256": hex.EncodeToString(h[:])}
	}
	m := map[string]any{"schema": payloadSchema, "repository": "storminator89/Tracebolt",
		"version": "v0.0.0-macos-candidate.1", "sourceCommit": "a" + string(bytes.Repeat([]byte("a"), 39)),
		"sourceTree": "b" + string(bytes.Repeat([]byte("b"), 39)), "goVersion": "go1.27.1",
		"target": "darwin/" + arch, "candidateKind": "publisher-unsigned-service-test",
		"nativeAccepted": false, "publisherSigned": false, "notarized": false,
		"published": false, "productionReady": false, "assets": assets}
	if mutateManifest != nil {
		mutateManifest(m)
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files["payload-manifest.json"] = append(manifest, '\n')
	members := make([]fixtureMember, 0, len(memberNames))
	for _, name := range memberNames {
		mode := int64(0644)
		if len(name) >= 4 && name[:4] == "bin/" {
			mode = 0755
		}
		members = append(members, fixtureMember{name: name, bytes: files[name], kind: tar.TypeReg, mode: mode})
	}
	if mutate != nil {
		members = mutate(members)
	}
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, 9)
	if err != nil {
		t.Fatal(err)
	}
	gz.Name = ""
	gz.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, member := range members {
		h := &tar.Header{Name: member.name, Typeflag: member.kind, Size: int64(len(member.bytes)), Mode: member.mode,
			Uid: 0, Gid: 0, ModTime: time.Unix(100, 0), Format: tar.FormatUSTAR}
		if member.kind != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if member.kind == tar.TypeReg {
			if _, err := tw.Write(member.bytes); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "package.tar.gz")
	if err := os.WriteFile(name, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return name, hex.EncodeToString(h[:])
}

func TestVerifySyntheticPackageAndReviewOnly(t *testing.T) {
	fixtureRoleInspector(t)
	for _, arch := range []string{"amd64", "arm64"} {
		filename, digest := fixtureArchive(t, arch, nil, nil)
		pkg, err := verifyPackage(filename, digest, arch)
		if err != nil || pkg.Digest != digest || pkg.Manifest.Target != "darwin/"+arch || len(pkg.Files) != len(memberNames) {
			t.Fatalf("verify %s: %v", arch, err)
		}
		if err := execute("verify", false, "", pkg, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRejectTamperedWrongTargetAndUnsafeArchive(t *testing.T) {
	fixtureRoleInspector(t)
	arch := "amd64"
	tests := map[string]struct {
		mutate func([]fixtureMember) []fixtureMember
		m      func(map[string]any)
	}{
		"duplicate":      {mutate: func(v []fixtureMember) []fixtureMember { return append(v, v[0]) }},
		"traversal":      {mutate: func(v []fixtureMember) []fixtureMember { v[0].name = "../TESTING.md"; return v }},
		"symlink":        {mutate: func(v []fixtureMember) []fixtureMember { v[0].kind = tar.TypeSymlink; return v }},
		"wrong mode":     {mutate: func(v []fixtureMember) []fixtureMember { v[1].mode = 0777; return v }},
		"missing":        {mutate: func(v []fixtureMember) []fixtureMember { return v[1:] }},
		"changed bytes":  {mutate: func(v []fixtureMember) []fixtureMember { v[0].bytes = []byte("other"); return v }},
		"false trust":    {m: func(v map[string]any) { v["nativeAccepted"] = true }},
		"extra manifest": {m: func(v map[string]any) { v["newAuthority"] = true }},
		"wrong role digest": {m: func(v map[string]any) {
			v["assets"].(map[string]any)["bin/macos-agent"] = map[string]any{"size": 20, "sha256": string(bytes.Repeat([]byte("0"), 64))}
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			filename, digest := fixtureArchive(t, arch, tc.mutate, tc.m)
			if _, err := verifyPackage(filename, digest, arch); err == nil {
				t.Fatal("unsafe package accepted")
			}
		})
	}
	filename, digest := fixtureArchive(t, arch, nil, nil)
	if _, err := verifyPackage(filename, digest, "arm64"); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	if _, err := verifyPackage(filename, string(bytes.Repeat([]byte("0"), 64)), arch); err == nil {
		t.Fatal("wrong selected hash accepted")
	}
	for _, change := range []struct {
		name string
		data func([]byte) []byte
	}{
		{"trailing bytes", func(b []byte) []byte { return append(b, []byte("unreviewed")...) }},
		{"damaged trailer", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
	} {
		t.Run(change.name, func(t *testing.T) {
			b, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			b = change.data(b)
			path := filepath.Join(t.TempDir(), "changed.tar.gz")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(b)
			if _, err := verifyPackage(path, hex.EncodeToString(h[:]), arch); err == nil {
				t.Fatal("unclosed compressed archive accepted")
			}
		})
	}
}

func TestProductionRoleInspectionNeedsRealGoMetadata(t *testing.T) {
	if checkRoleBuildInfo(fixtureMacho("amd64", "bin/macos-agent"), "bin/macos-agent", "amd64") == nil {
		t.Fatal("Mach-O header alone accepted as Go role proof")
	}
}

func TestBootstrapSelectionIsHashBoundAndStageValidatesTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public-bootstrap.json")
	raw := []byte(`{"not":"a valid bootstrap"}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	digest := hex.EncodeToString(h[:])
	if _, err := readBootstrap(path, digest, "basic-readonly-v1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrap(path, digest, "basic-readonly-v1", true); err == nil {
		t.Fatal("invalid public trust accepted for fresh stage")
	}
	if _, err := readBootstrap(path, string(bytes.Repeat([]byte("0"), 64)), "basic-readonly-v1", false); err == nil {
		t.Fatal("changed public bootstrap accepted")
	}
	if _, err := readBootstrap(path, digest, "other-profile", false); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestSelectedInputsRejectLinksAndFIFOsWithoutBlocking(t *testing.T) {
	fixtureRoleInspector(t)
	filename, digest := fixtureArchive(t, "amd64", nil, nil)
	dir := t.TempDir()
	link := filepath.Join(dir, "archive-link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPackage(link, digest, "amd64"); err == nil {
		t.Fatal("linked archive accepted")
	}
	if _, err := readBootstrap(link, digest, "basic-readonly-v1", false); err == nil {
		t.Fatal("linked bootstrap accepted")
	}
	fifo := filepath.Join(dir, "input-fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("FIFO fixture unavailable: %v", err)
	}
	if _, err := verifyPackage(fifo, digest, "amd64"); err == nil {
		t.Fatal("FIFO archive accepted")
	}
	if _, err := readBootstrap(fifo, digest, "basic-readonly-v1", false); err == nil {
		t.Fatal("FIFO bootstrap accepted")
	}
}

type fakeStage struct {
	inspect, apply, rollback int
	reject                   bool
}

func (f *fakeStage) Inspect(_, _ uint32, _ packageBytes, _ bool) error {
	f.inspect++
	if f.reject {
		return errRejected
	}
	return nil
}
func (f *fakeStage) Apply(_, _ uint32, _ packageBytes) error    { f.apply++; return nil }
func (f *fakeStage) Rollback(_, _ uint32, _ packageBytes) error { f.rollback++; return nil }

func TestStageRequiresExplicitApplyAndIdentity(t *testing.T) {
	pkg := packageBytes{}
	f := &fakeStage{}
	if execute("stage", false, "502:502", pkg, f) != nil || f.inspect != 1 || f.apply != 0 {
		t.Fatalf("review mutated: %+v", f)
	}
	if execute("rollback", false, "502:502", pkg, f) != nil || f.rollback != 0 {
		t.Fatalf("rollback review mutated: %+v", f)
	}
	if execute("stage", true, "502:502", pkg, f) != nil || f.apply != 1 {
		t.Fatalf("explicit stage failed: %+v", f)
	}
	if execute("rollback", true, "502:502", pkg, f) != nil || f.rollback != 1 {
		t.Fatalf("explicit rollback failed: %+v", f)
	}
	for _, id := range []string{"", "0:502", "501:502", "502:0", "502:502:502", "0502:502", "502:999999"} {
		if execute("stage", true, id, pkg, f) == nil {
			t.Errorf("accepted %q", id)
		}
	}
	if execute("verify", true, "", pkg, f) == nil || execute("uninstall", true, "502:502", pkg, f) == nil {
		t.Fatal("unsupported action accepted")
	}
	f.reject = true
	before := f.apply
	if execute("stage", true, "502:502", pkg, f) == nil || f.apply != before {
		t.Fatal("applied after rejected preflight")
	}
}

func TestVerifyCommandDoesNotRequireHostOrRoot(t *testing.T) {
	fixtureRoleInspector(t)
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("synthetic fixture only supports Darwin target architectures")
	}
	filename, digest := fixtureArchive(t, runtime.GOARCH, nil, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--archive", filename, "--package-sha256", digest}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("read-only verify rejected: %d %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"nativeAccepted":false`)) {
		t.Fatal("trust boundary missing")
	}
}
