package windowspackage

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// A data-only PE fixture. No executable is written or started by these tests.
func fixturePE(architecture string) []byte {
	payload := make([]byte, 1024)
	copy(payload, "MZ")
	binary.LittleEndian.PutUint32(payload[0x3c:], 0x80)
	copy(payload[0x80:], "PE\x00\x00")
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if architecture == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	var header bytes.Buffer
	_ = binary.Write(&header, binary.LittleEndian, pe.FileHeader{Machine: machine, NumberOfSections: 1, SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE})
	_ = binary.Write(&header, binary.LittleEndian, pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: 0x1000, ImageBase: 0x140000000, SectionAlignment: 4096, FileAlignment: 512, SizeOfImage: 8192, SizeOfHeaders: 512, Subsystem: 3, NumberOfRvaAndSizes: 16})
	copy(payload[0x84:], header.Bytes())
	section := 0x84 + 20 + 240
	copy(payload[section:], ".text")
	binary.LittleEndian.PutUint32(payload[section+8:], 1)
	binary.LittleEndian.PutUint32(payload[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(payload[section+16:], 512)
	binary.LittleEndian.PutUint32(payload[section+20:], 512)
	binary.LittleEndian.PutUint32(payload[section+36:], 0x60000020)
	payload[512] = 0xc3
	return payload
}
func fixtureManifest(payload []byte, architecture string) Manifest {
	digest := sha256.Sum256(payload)
	return Manifest{ManifestSchema, "v0.1.0-rc.1", strings.Repeat("a", 40), architecture, hex.EncodeToString(digest[:])}
}
func TestManifestValidPEArchitectures(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		p := fixturePE(arch)
		m := fixtureManifest(p, arch)
		if err := m.Validate(p); err != nil {
			t.Fatal(arch, err)
		}
		raw, _ := json.Marshal(m)
		got, err := ParseManifest(append(raw, '\n'))
		if err != nil || got != m {
			t.Fatal(got, err)
		}
	}
}
func TestManifestRejectsFields(t *testing.T) {
	payload := fixturePE("amd64")
	for _, tc := range []struct {
		name string
		edit func(*Manifest)
	}{
		{"schema", func(m *Manifest) { m.SchemaVersion = "other" }},
		{"version_missing", func(m *Manifest) { m.Version = "" }},
		{"version_unprefixed", func(m *Manifest) { m.Version = "1.0.0" }},
		{"version_leading_zero", func(m *Manifest) { m.Version = "v01.0.0" }},
		{"prerelease_zero", func(m *Manifest) { m.Version = "v1.0.0-01" }},
		{"version_newline", func(m *Manifest) { m.Version = "v1.0.0\n" }},
		{"version_oversize", func(m *Manifest) { m.Version = "v1.0.0+" + strings.Repeat("x", 80) }},
		{"commit_short", func(m *Manifest) { m.SourceCommit = strings.Repeat("a", 39) }},
		{"commit_uppercase", func(m *Manifest) { m.SourceCommit = strings.Repeat("A", 40) }},
		{"commit_nonhex", func(m *Manifest) { m.SourceCommit = strings.Repeat("z", 40) }},
		{"sha_uppercase", func(m *Manifest) { m.SHA256 = strings.ToUpper(m.SHA256) }},
		{"sha_short", func(m *Manifest) { m.SHA256 = "a" }},
		{"architecture", func(m *Manifest) { m.Architecture = "386" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureManifest(payload, "amd64")
			tc.edit(&m)
			if m.Validate(payload) == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	for _, version := range []string{"v0.0.0", "v1.2.3", "v1.2.3-alpha.1+build.001", "v1.2.3-0", "v1.2.3-x-y"} {
		m := fixtureManifest(payload, "amd64")
		m.Version = version
		if err := m.Validate(payload); err != nil {
			t.Fatal(version, err)
		}
	}
}
func TestManifestRejectsPayloads(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func([]byte)
	}{
		{"mz", "payload-pe", func(p []byte) { p[0] = 0 }},
		{"pe", "payload-pe", func(p []byte) { p[0x80] = 0 }},
		{"machine", "payload-machine", func(p []byte) { binary.LittleEndian.PutUint16(p[0x84:], pe.IMAGE_FILE_MACHINE_ARM64) }},
		{"dll", "payload-pe", func(p []byte) {
			binary.LittleEndian.PutUint16(p[0x84+18:], pe.IMAGE_FILE_DLL|pe.IMAGE_FILE_EXECUTABLE_IMAGE)
		}},
		{"not_executable", "payload-pe", func(p []byte) { binary.LittleEndian.PutUint16(p[0x84+18:], 0) }},
		{"no_sections", "payload-pe", func(p []byte) { binary.LittleEndian.PutUint16(p[0x84+2:], 0) }},
		{"bad_optional", "payload-pe", func(p []byte) { binary.LittleEndian.PutUint16(p[0x84+20:], 0x10b) }},
		{"zero_entry", "payload-pe", func(p []byte) { binary.LittleEndian.PutUint32(p[0x84+20+16:], 0) }},
		{"section_out_of_file", "payload-pe", func(p []byte) { binary.LittleEndian.PutUint32(p[0x84+20+240+20:], 0xfffffff0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePE("amd64")
			tc.edit(p)
			m := fixtureManifest(p, "amd64")
			if got := Code(m.Validate(p)); got != tc.code {
				t.Fatalf("got %s want %s", got, tc.code)
			}
		})
	}
	payload := fixturePE("amd64")
	m := fixtureManifest(payload, "amd64")
	payload[700]++
	if Code(m.Validate(payload)) != "payload-digest" {
		t.Fatal("hash mismatch accepted")
	}
	if Code(m.Validate(payload[:511])) != "payload-size" {
		t.Fatal("tiny payload accepted")
	}
	oversized := make([]byte, MaxPayloadBytes+1)
	if Code(m.Validate(oversized)) != "payload-size" {
		t.Fatal("oversize payload accepted")
	}
}
func TestParseManifestStrict(t *testing.T) {
	payload := fixturePE("amd64")
	m := fixtureManifest(payload, "amd64")
	raw, _ := json.Marshal(m)
	for _, invalid := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("{}"), append(append([]byte{}, raw...), []byte("{}")...),
		[]byte(strings.Replace(string(raw), `"version":`, `"unknown":`, 1)),
		[]byte(strings.Replace(string(raw), `"version":`, `"version":"v2.0.0","version":`, 1)),
		[]byte(strings.Replace(string(raw), `"version":"v0.1.0-rc.1"`, `"version":3`, 1)),
		[]byte(strings.Replace(string(raw), `"version":"v0.1.0-rc.1"`, `"version":null`, 1)),
		bytes.Repeat([]byte(" "), 4097),
	} {
		if _, err := ParseManifest(invalid); err == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}

func TestPEMetadataBoundsBeforeDecoder(t *testing.T) {
	for _, edit := range []func([]byte){
		func(p []byte) { binary.LittleEndian.PutUint32(p[0x3c:], 0xffffffff) },
		func(p []byte) { binary.LittleEndian.PutUint16(p[0x84+2:], 97) },
		func(p []byte) { binary.LittleEndian.PutUint32(p[0x84+12:], 1<<19) },
		func(p []byte) { binary.LittleEndian.PutUint32(p[0x84+12:], 1) },
		func(p []byte) { binary.LittleEndian.PutUint32(p[0x84+8:], 0xffffffff) },
		func(p []byte) { binary.LittleEndian.PutUint16(p[0x84+20+240+32:], 1) },
	} {
		p := fixturePE("amd64")
		edit(p)
		if boundedPEHeaders(p) {
			t.Fatal("unbounded PE metadata accepted")
		}
		if Code(fixtureManifest(p, "amd64").Validate(p)) != "payload-pe" {
			t.Fatal("metadata bypassed validation")
		}
	}
}
