//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

const readAdminARM64PriorSource = "7b20a93e481feb1f7433ee0ef6c912a35f68ce6d"
const readAdminARM64PriorVersion = "source-built-7b20a93"

type readAdminSourceFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type readAdminSourceGeneration struct {
	SourceCommit string                         `json:"sourceCommit"`
	Files        map[string]readAdminSourceFile `json:"files"`
}
type readAdminSourceBuildProof struct {
	SchemaVersion         string                    `json:"schemaVersion"`
	Architecture          string                    `json:"architecture"`
	BaselineKind          string                    `json:"baselineKind"`
	PriorSourceCommit     string                    `json:"priorSourceCommit"`
	CandidateSourceCommit string                    `json:"candidateSourceCommit"`
	Prior                 readAdminSourceGeneration `json:"prior"`
	Candidate             readAdminSourceGeneration `json:"candidate"`
}

func readAdminArchitectureSelection(selected, host, runner, upgrade, source string) error {
	if selected != "amd64" && selected != "arm64" || selected != host || map[string]string{"amd64": "X64", "arm64": "ARM64"}[selected] != runner {
		return errors.New("native architecture selection rejected")
	}
	if selected == "arm64" && (upgrade != "true" || source == readAdminARM64PriorSource) {
		return errors.New("distinct approved ARM64 upgrade required")
	}
	return nil
}

func readAdminDecodeSourceProof(raw []byte, candidate string) (*readAdminSourceBuildProof, error) {
	bad := errors.New("invalid source fixture proof")
	if len(raw) == 0 || len(raw) > 16384 {
		return nil, bad
	}
	// A canonical roundtrip also rejects duplicate fields and alternate encodings.
	var generic any
	if json.Unmarshal(raw, &generic) != nil {
		return nil, bad
	}
	canonical, err := json.Marshal(generic)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return nil, bad
	}
	var p readAdminSourceBuildProof
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return nil, bad
	}
	typed, _ := json.Marshal(p)
	var normalized any
	if json.Unmarshal(typed, &normalized) != nil {
		return nil, bad
	}
	typed, _ = json.Marshal(normalized)
	if !bytes.Equal(raw, append(typed, '\n')) {
		return nil, bad
	}

	if p.SchemaVersion != "tracebolt.arm64-source-upgrade-fixture.v1" || p.Architecture != "arm64" || p.BaselineKind != "source-built" || p.PriorSourceCommit != readAdminARM64PriorSource || p.CandidateSourceCommit != candidate || candidate == readAdminARM64PriorSource || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(candidate) || p.Prior.SourceCommit != p.PriorSourceCommit || p.Candidate.SourceCommit != candidate {
		return nil, bad
	}
	for _, generation := range []readAdminSourceGeneration{p.Prior, p.Candidate} {
		if len(generation.Files) != 5 {
			return nil, bad
		}
		for _, role := range []string{"agent-service", "enroll-agent", "lan-agent", "socket-owner-reader", "source"} {
			f, ok := generation.Files[role]
			limit := int64(128 << 20)
			if role == "source" {
				limit = 256 << 20
			}
			if !ok || f.Size <= 0 || f.Size > limit || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(f.SHA256) || f.SHA256 == string(bytes.Repeat([]byte("0"), 64)) {
				return nil, bad
			}
		}
	}
	if p.Prior.Files["lan-agent"].SHA256 == p.Candidate.Files["lan-agent"].SHA256 || p.Prior.Files["source"].SHA256 == p.Candidate.Files["source"].SHA256 {
		return nil, bad
	}
	return &p, nil
}

func readAdminVerifySourceBinary(f *os.File, role, source string) bool {
	var header [64]byte
	if _, err := f.ReadAt(header[:], 0); err != nil || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 || binary.LittleEndian.Uint16(header[18:20]) != 183 || (binary.LittleEndian.Uint16(header[16:18]) != 2 && binary.LittleEndian.Uint16(header[16:18]) != 3) || binary.LittleEndian.Uint32(header[20:24]) != 1 {
		return false
	}
	info, err := buildinfo.Read(f)
	if err != nil || info.Path != "localrmm/cmd/"+role || info.Main.Path != "localrmm" || info.GoVersion != runtime.Version() {
		return false
	}
	settings := map[string]string{}
	for _, v := range info.Settings {
		if _, ok := settings[v.Key]; ok {
			return false
		}
		settings[v.Key] = v.Value
	}
	for key, want := range map[string]string{"GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0", "CGO_ENABLED": "0", "-trimpath": "true", "vcs": "git", "vcs.revision": source, "vcs.modified": "false"} {
		if settings[key] != want {
			return false
		}
	}
	return true
}

func readAdminVerifySourceFiles(t *testing.T, generation readAdminSourceGeneration, paths map[string]string) {
	t.Helper()
	for role, want := range generation.Files {
		path := paths[role]
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() != want.Size || systemdHash(t, path) != want.SHA256 {
			t.Fatal("source-bound ARM64 artifact mismatch")
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal("source-bound ARM64 artifact unavailable")
		}
		opened, e := f.Stat()
		ok := e == nil && os.SameFile(before, opened)
		if role != "source" {
			ok = ok && readAdminVerifySourceBinary(f, role, generation.SourceCommit)
		}
		after, e := f.Stat()
		_ = f.Close()
		if !ok || e != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || systemdHash(t, path) != want.SHA256 {
			t.Fatal("ARM64 ELF or commit build provenance rejected")
		}
	}
}

func readAdminLoadSourceFixture(t *testing.T, options *readAdminNativeOptions, binaries map[string]string, archive string) {
	t.Helper()
	if options.architecture != "arm64" || runtime.GOARCH != "arm64" || !options.upgradeApproved {
		t.Fatal("ARM64 source fixture gate required")
	}
	dir := os.Getenv("TRACEBOLT_READ_ADMIN_ARM64_FIXTURE_DIRECTORY")
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		t.Fatal("exact ARM64 fixture directory required")
	}
	pth := filepath.Join(dir, "proof.json")
	st, e := os.Lstat(pth)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() <= 0 || st.Size() > 16384 {
		t.Fatal("private ARM64 source proof unavailable")
	}
	raw, e := os.ReadFile(pth)
	if e != nil {
		t.Fatal("ARM64 source proof read")
	}
	proof, e := readAdminDecodeSourceProof(raw, options.source)
	if e != nil {
		t.Fatal("ARM64 source proof rejected")
	}
	prior := map[string]string{}
	for role := range proof.Prior.Files {
		name := role
		if role == "source" {
			name = "source.tar"
		}
		prior[role] = filepath.Join(dir, "prior", name)
	}
	readAdminVerifySourceFiles(t, proof.Prior, prior)
	candidate := map[string]string{"source": archive}
	for role, path := range binaries {
		if role != "lan-manager" {
			candidate[role] = path
		}
	}
	readAdminVerifySourceFiles(t, proof.Candidate, candidate)
	// The candidate-owned read-only compatibility checker is distinct from every
	// generation's production bootstrap admission. No runtime target is changed.
	f, e := os.Open(archive)
	if e != nil {
		t.Fatal("candidate source unavailable")
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var host []byte
	members := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		members++
		if e != nil || members > 10000 {
			t.Fatal("candidate source archive invalid")
		}
		if h.Name != "deploy/release/linux-bootstrap.py" {
			continue
		}
		if host != nil || !h.FileInfo().Mode().IsRegular() || h.Size <= 0 || h.Size > 131072 {
			t.Fatal("candidate host preflight member rejected")
		}
		host, e = io.ReadAll(io.LimitReader(tr, 131073))
		if e != nil || int64(len(host)) != h.Size {
			t.Fatal("candidate host preflight read")
		}
	}
	if host == nil || systemdHash(t, archive) != proof.Candidate.Files["source"].SHA256 {
		t.Fatal("candidate source host preflight unbound")
	}
	options.sourceBuild = proof
	options.priorArtifacts = prior
	options.hostPreflight = host
}

func (o *readAdminNativeOptions) priorSource() string {
	if o.architecture == "arm64" {
		return readAdminARM64PriorSource
	}
	return readAdminPriorSource
}
func (o *readAdminNativeOptions) priorHashes() map[string]string {
	if o.architecture != "arm64" {
		return readAdminPriorHashes
	}
	out := map[string]string{}
	if o.sourceBuild != nil {
		for role, f := range o.sourceBuild.Prior.Files {
			out[role] = f.SHA256
		}
	}
	return out
}

func TestReadAdminARM64SourceFixtureContract(t *testing.T) {
	source := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		arch, host, runner, approval, source string
		ok                                   bool
	}{
		{"amd64", "amd64", "X64", "false", source, true}, {"arm64", "arm64", "ARM64", "true", source, true},
		{"arm64", "arm64", "ARM64", "false", source, false}, {"arm64", "amd64", "ARM64", "true", source, false},
		{"arm64", "arm64", "X64", "true", source, false}, {"arm64", "arm64", "ARM64", "true", readAdminARM64PriorSource, false}, {"armhf", "arm", "ARM", "true", source, false},
	} {
		if (readAdminArchitectureSelection(tc.arch, tc.host, tc.runner, tc.approval, tc.source) == nil) != tc.ok {
			t.Fatal("architecture approval boundary changed")
		}
	}
	files := func(d string) map[string]readAdminSourceFile {
		m := map[string]readAdminSourceFile{}
		for _, role := range []string{"agent-service", "enroll-agent", "lan-agent", "socket-owner-reader", "source"} {
			m[role] = readAdminSourceFile{1, string(bytes.Repeat([]byte(d), 64))}
		}
		return m
	}
	p := readAdminSourceBuildProof{"tracebolt.arm64-source-upgrade-fixture.v1", "arm64", "source-built", readAdminARM64PriorSource, source, readAdminSourceGeneration{readAdminARM64PriorSource, files("b")}, readAdminSourceGeneration{source, files("c")}}
	encode := func(p readAdminSourceBuildProof) []byte {
		raw, _ := json.Marshal(p)
		var generic any
		_ = json.Unmarshal(raw, &generic)
		raw, _ = json.Marshal(generic)
		return append(raw, '\n')
	}
	raw := encode(p)
	if _, e := readAdminDecodeSourceProof(raw, source); e != nil {
		t.Fatal("exact generated source proof rejected")
	}
	for _, bad := range [][]byte{append(raw, raw...), bytes.Replace(raw, []byte(`"architecture":"arm64"`), []byte(`"architecture":"amd64"`), 1), bytes.Replace(raw, []byte(`"architecture"`), []byte(`"Architecture"`), 1), bytes.Replace(raw, []byte(`"sourceCommit"`), []byte(`"SourceCommit"`), 1), bytes.Replace(raw, []byte(`"baselineKind":"source-built"`), []byte(`"baselineKind":"published-release"`), 1), bytes.Replace(raw, []byte(`"architecture":"arm64"`), []byte(`"architecture":"arm64","architecture":"arm64"`), 1)} {
		if _, e := readAdminDecodeSourceProof(bad, source); e == nil {
			t.Fatal("inexact source proof accepted")
		}
	}
	p.Candidate.Files["lan-agent"] = p.Prior.Files["lan-agent"]
	if _, e := readAdminDecodeSourceProof(encode(p), source); e == nil {
		t.Fatal("same binary falsely presented as upgrade")
	}
}
