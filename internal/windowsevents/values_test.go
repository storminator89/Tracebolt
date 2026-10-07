package windowsevents

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

const fixtureBase = uint64(0x10000)

func fixtureValues() []byte {
	buffer := make([]byte, metadataPropertyCount*variantSize)
	values := []uint64{37, 42, 4, 0, 134117966450000006, 0}
	types := []uint32{variantUInt64, variantUInt16, variantByte, variantString, variantFileTime, variantString}
	for i := range types {
		binary.LittleEndian.PutUint64(buffer[i*variantSize:], values[i])
		binary.LittleEndian.PutUint32(buffer[i*variantSize+12:], types[i])
	}
	for _, pair := range []struct {
		index int
		text  string
	}{{3, "Tracebolt-Fixture"}, {5, "System"}} {
		binary.LittleEndian.PutUint64(buffer[pair.index*variantSize:], fixtureBase+uint64(len(buffer)))
		for _, u := range append(utf16.Encode([]rune(pair.text)), 0) {
			buffer = binary.LittleEndian.AppendUint16(buffer, u)
		}
	}
	return buffer
}

func TestParseSelectedValues(t *testing.T) {
	event, err := parseMetadataValues(fixtureValues(), fixtureBase, metadataPropertyCount, "System")
	if err != nil {
		t.Fatal(err)
	}
	if event.RecordID != 37 || event.EventID != 42 || event.Level != 4 || event.Provider != "Tracebolt-Fixture" ||
		event.Channel != "System" || event.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00") != "2026-01-02T03:04:05.000000600Z" {
		t.Fatal("synthetic metadata did not decode exactly")
	}
}

func TestScalarUnusedStorageIsIgnored(t *testing.T) {
	b := fixtureValues()
	for _, at := range []int{variantSize, 2 * variantSize} {
		b[at+7] = 0xff
		binary.LittleEndian.PutUint32(b[at+8:], 0xffffffff)
	}
	event, err := parseMetadataValues(b, fixtureBase, metadataPropertyCount, "System")
	if err != nil || event.EventID != 42 || event.Level != 4 {
		t.Fatal("undefined scalar union bytes were interpreted")
	}
}

func TestRejectMalformedMetadata(t *testing.T) {
	tests := map[string]func([]byte) []byte{
		"short":      func(b []byte) []byte { return b[:95] },
		"oversize":   func(b []byte) []byte { return make([]byte, maxRenderBytes+1) },
		"wrong type": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], variantString); return b },
		"null":       func(b []byte) []byte { binary.LittleEndian.PutUint32(b[2*variantSize+12:], 0); return b },
		"array": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[3*variantSize+12:], variantString|128)
			return b
		},
		"zero record":             func(b []byte) []byte { binary.LittleEndian.PutUint64(b, 0); return b },
		"pointer before base":     func(b []byte) []byte { binary.LittleEndian.PutUint64(b[3*variantSize:], fixtureBase-1); return b },
		"pointer inside variants": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[3*variantSize:], fixtureBase); return b },
		"pointer outside buffer": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(b[3*variantSize:], fixtureBase+uint64(len(b)))
			return b
		},
		"pointer overflow":   func(b []byte) []byte { binary.LittleEndian.PutUint64(b[3*variantSize:], ^uint64(0)); return b },
		"unaligned pointer":  func(b []byte) []byte { binary.LittleEndian.PutUint64(b[3*variantSize:], fixtureBase+97); return b },
		"unterminated":       func(b []byte) []byte { return b[:len(b)-2] },
		"control":            func(b []byte) []byte { binary.LittleEndian.PutUint16(b[96:], '\n'); return b },
		"surrogate":          func(b []byte) []byte { binary.LittleEndian.PutUint16(b[96:], 0xd800); return b },
		"timestamp overflow": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[4*variantSize:], ^uint64(0)); return b },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMetadataValues(mutate(fixtureValues()), fixtureBase, metadataPropertyCount, "System"); !errors.Is(err, ErrInvalidData) {
				t.Fatal("malformed metadata was accepted")
			}
		})
	}
	for _, count := range []uint32{0, 5, 7, 0xffffffff} {
		if _, err := parseMetadataValues(fixtureValues(), fixtureBase, count, "System"); err == nil {
			t.Fatal("wrong property count was accepted")
		}
	}
	if _, err := parseMetadataValues(fixtureValues(), fixtureBase, 6, "Application"); err == nil {
		t.Fatal("wrong channel was accepted")
	}
}

func TestProviderBounds(t *testing.T) {
	for _, s := range []string{"", " leading", "trailing ", "line\nbreak", "null\x00", "\u202ehidden", strings.Repeat("x", maxProviderUnits+1)} {
		if validProvider(s) {
			t.Fatal("unsafe provider label accepted")
		}
	}
	if !validProvider(strings.Repeat("x", maxProviderUnits)) || !validProvider("Synthetic-😀-Provider") {
		t.Fatal("valid provider label rejected")
	}
	b := make([]byte, metadataPropertyCount*variantSize)
	for i := 0; i < maxProviderUnits+1; i++ {
		b = binary.LittleEndian.AppendUint16(b, 'x')
	}
	b = binary.LittleEndian.AppendUint16(b, 0)
	if _, err := valueString(b, fixtureBase, fixtureBase+96, maxProviderUnits); err == nil {
		t.Fatal("oversized UTF-16 label accepted")
	}
}

func FuzzMetadataValues(f *testing.F) {
	f.Add(fixtureValues(), uint64(fixtureBase), uint32(6))
	f.Add([]byte{}, uint64(0), uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, base uint64, count uint32) {
		event, err := parseMetadataValues(b, base, count, "System")
		if err == nil && !validEvent(event, "System") {
			t.Fatal("invalid event escaped parser")
		}
	})
}
