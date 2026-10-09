package windowspackage

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// Manifest is the embedded public provenance record. A digest binds the embedded
// bytes, not publisher identity, Authenticode signing, or a release approval.
type Manifest struct {
	SchemaVersion string `json:"schemaVersion"`
	Version       string `json:"version"`
	SourceCommit  string `json:"sourceCommit"`
	Architecture  string `json:"architecture"`
	SHA256        string `json:"sha256"`
}

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func validVersion(v string) bool {
	if len(v) > 80 || !versionPattern.MatchString(v) {
		return false
	}
	core := strings.SplitN(v, "+", 2)[0]
	if split := strings.SplitN(core, "-", 2); len(split) == 2 {
		for _, part := range strings.Split(split[1], ".") {
			numeric := true
			for _, c := range part {
				if c < '0' || c > '9' {
					numeric = false
				}
			}
			if numeric && len(part) > 1 && part[0] == '0' {
				return false
			}
		}
	}
	return true
}
func lowerHex(v string, size int) bool {
	if len(v) != size {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (m Manifest) validateFields() error {
	if m.SchemaVersion != ManifestSchema || !validVersion(m.Version) || !lowerHex(m.SourceCommit, 40) || !lowerHex(m.SHA256, 64) {
		return failure("manifest-invalid")
	}
	if m.Architecture != "amd64" && m.Architecture != "arm64" {
		return failure("architecture-invalid")
	}
	return nil
}

// ParseManifest rejects unknown, duplicated, missing and trailing fields.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > 4096 {
		return m, failure("manifest-invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return m, failure("manifest-invalid")
	}
	values := make(map[string]string, 5)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return m, failure("manifest-invalid")
		}
		if _, found := values[key]; found {
			return m, failure("manifest-invalid")
		}
		switch key {
		case "schemaVersion", "version", "sourceCommit", "architecture", "sha256":
		default:
			return m, failure("manifest-invalid")
		}
		var value string
		if decoder.Decode(&value) != nil {
			return m, failure("manifest-invalid")
		}
		values[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return m, failure("manifest-invalid")
	}
	if _, err = decoder.Token(); err != io.EOF || len(values) != 5 {
		return m, failure("manifest-invalid")
	}
	m = Manifest{values["schemaVersion"], values["version"], values["sourceCommit"], values["architecture"], values["sha256"]}
	if err = m.validateFields(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate bounds and hashes the bytes and requires a PE32+ executable with the
// manifest's exact machine, a real image header and bounded file-backed sections.
func (m Manifest) Validate(payload []byte) error {
	if err := m.validateFields(); err != nil {
		return err
	}
	if len(payload) < 512 || len(payload) > MaxPayloadBytes {
		return failure("payload-size")
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != m.SHA256 {
		return failure("payload-digest")
	}
	if !boundedPEHeaders(payload) {
		return failure("payload-pe")
	}
	image, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return failure("payload-pe")
	}
	defer image.Close()
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if m.Architecture == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	if image.Machine != machine {
		return failure("payload-machine")
	}
	header, ok := image.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || header.Magic != 0x20b || image.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || image.Characteristics&pe.IMAGE_FILE_DLL != 0 || image.NumberOfSections == 0 || image.NumberOfSections > 96 || header.SizeOfImage == 0 || header.AddressOfEntryPoint == 0 || header.AddressOfEntryPoint >= header.SizeOfImage || header.SizeOfHeaders == 0 || uint64(header.SizeOfHeaders) > uint64(len(payload)) {
		return failure("payload-pe")
	}
	for _, section := range image.Sections {
		if uint64(section.Offset)+uint64(section.Size) > uint64(len(payload)) {
			return failure("payload-pe")
		}
	}
	return nil
}

// Bound allocation-driving COFF metadata before handing bytes to debug/pe. The
// image/file limit alone would allow amplified symbol/relocation allocations.
func boundedPEHeaders(payload []byte) bool {
	if len(payload) < 512 || payload[0] != 'M' || payload[1] != 'Z' {
		return false
	}
	offset := uint64(binary.LittleEndian.Uint32(payload[0x3c:0x40]))
	if offset < 64 || offset+24 > uint64(len(payload)) || string(payload[offset:offset+4]) != "PE\x00\x00" {
		return false
	}
	header := payload[offset+4 : offset+24]
	sections := uint64(binary.LittleEndian.Uint16(header[2:4]))
	symbols := uint64(binary.LittleEndian.Uint32(header[12:16]))
	symbolsOffset := uint64(binary.LittleEndian.Uint32(header[8:12]))
	optionalSize := uint64(binary.LittleEndian.Uint16(header[16:18]))
	if sections == 0 || sections > 96 || optionalSize != 240 || symbols > 1<<18 {
		return false
	}
	if symbolsOffset == 0 && symbols != 0 {
		return false
	}
	if symbolsOffset != 0 {
		end := symbolsOffset + symbols*18
		if end+4 > uint64(len(payload)) {
			return false
		}
		stringsSize := uint64(binary.LittleEndian.Uint32(payload[end : end+4]))
		if stringsSize < 4 || stringsSize > 4<<20 || end+stringsSize > uint64(len(payload)) {
			return false
		}
	}
	sectionOffset := offset + 24 + optionalSize
	if sectionOffset+sections*40 > uint64(len(payload)) {
		return false
	}
	var relocationCount uint64
	for i := uint64(0); i < sections; i++ {
		section := payload[sectionOffset+i*40 : sectionOffset+(i+1)*40]
		count := uint64(binary.LittleEndian.Uint16(section[32:34]))
		relocations := uint64(binary.LittleEndian.Uint32(section[24:28]))
		relocationCount += count
		if relocationCount > 1<<16 || count != 0 && (relocations == 0 || relocations+count*10 > uint64(len(payload))) {
			return false
		}
	}
	return true
}
