package fullinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/linuxpackages"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalHashVectors(t *testing.T) {
	m, c := buildFixture(t, 1)
	if m.CanonicalRowBytes != 195 || m.RowsSHA256 != "eb5060479d38deb1870340f021be9237186c0357adefbd6d851012e2a74e7703" {
		t.Fatalf("row vector changed: %d %s", m.CanonicalRowBytes, m.RowsSHA256)
	}
	md, err := ManifestDigest(m)
	if err != nil || md != "ea7412b5328c5c6fde125893da03dd642776733e67875c3ed3e7c4e2dfe132fa" {
		t.Fatalf("manifest vector: %v %s", err, md)
	}
	if c[0].SHA256 != "3027b5a4f7ecf694897755eae0e75457eb14b3190108e12a8c79129eb8f8c3e9" {
		t.Fatalf("chunk vector: %s", c[0].SHA256)
	}
}
func TestStrictDecodersAndCanonicalization(t *testing.T) {
	m, c := buildFixture(t, 2)
	mb, _ := json.Marshal(m)
	cb, _ := json.Marshal(c[0])
	got, err := DecodeManifest(mb)
	if err != nil || !reflect.DeepEqual(m, got) {
		t.Fatal("manifest round trip", err)
	}
	chunk, err := DecodeChunk(cb)
	if err != nil || !reflect.DeepEqual(c[0], chunk) {
		t.Fatal("chunk round trip", err)
	}
	pretty, _ := json.MarshalIndent(c[0], "", "  ")
	chunk, err = DecodeChunk(pretty)
	if err != nil || chunk.SHA256 != c[0].SHA256 {
		t.Fatal("whitespace changed canonical hash")
	}
	mutations := map[string]func([]byte) []byte{
		"duplicate root": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schemaVersion":`), []byte(`"schemaVersion":"ignored","schemaVersion":`), 1)
		},
		"case folded key": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1)
		},
		"unknown": func(b []byte) []byte { return append([]byte(`{"extra":0,`), b[1:]...) },
		"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"schemaVersion":"`+SchemaVersion+`",`), nil, 1) },
		"null string": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schemaVersion":"`+SchemaVersion+`"`), []byte(`"schemaVersion":null`), 1)
		},
		"extra document": func(b []byte) []byte { return append(b, []byte(` {}`)...) },
		"trailing data":  func(b []byte) []byte { return append(b, 'x') },
		"invalid utf8":   func(b []byte) []byte { return append(b, 0xff) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeManifest(mutate(bytes.Clone(mb))); err == nil || !reflect.DeepEqual(got, Manifest{}) {
				t.Fatal("accepted bad manifest")
			}
			if got, err := DecodeChunk(mutate(bytes.Clone(cb))); err == nil || !reflect.DeepEqual(got, Chunk{}) {
				t.Fatal("accepted bad chunk")
			}
		})
	}
	manifestBad := []string{
		strings.Replace(string(mb), `"durationMs":42`, `"durationMs":4.2e1`, 1),
		strings.Replace(string(mb), `"durationMs":42`, `"durationMs":-0`, 1),
		strings.Replace(string(mb), `"durationMs":42`, `"durationMs":null`, 1),
		strings.Replace(string(mb), `"observedCount":2`, `"observedCount":18446744073709551616`, 1),
		strings.Replace(string(mb), `"chunkCount":1`, `"chunkCount":4294967296`, 1),
		strings.Replace(string(mb), `"quality":"healthy"`, `"quality":"unknown","quality":"healthy"`, 1),
		strings.Replace(string(mb), `"id":"debian"`, `"id":"debian","id":"debian"`, 1),
		strings.Replace(string(mb), `"collectedAt":"2026-10-04T09:00:00.000000123Z"`, `"collectedAt":"2026-10-04T09:00:00.000000123+00:00"`, 1),
	}
	for _, bad := range manifestBad {
		if _, err := DecodeManifest([]byte(bad)); err == nil {
			t.Fatal("accepted malformed manifest")
		}
	}
	chunkBad := []string{
		strings.Replace(string(cb), `"ordinal":0`, `"ordinal":0.0`, 1),
		strings.Replace(string(cb), `"rowOffset":0`, `"rowOffset":-0`, 1),
		strings.Replace(string(cb), `"rowOffset":0`, `"rowOffset":18446744073709551616`, 1),
		strings.Replace(string(cb), `"name":"pkg-000000"`, `"name":"pkg-000000","name":"pkg-000000"`, 1),
		strings.Replace(string(cb), `"name":"pkg-000000"`, `"name":null`, 1),
		strings.Replace(string(cb), `"items":[`, `"items":null,"ignored":[`, 1),
	}
	for _, bad := range chunkBad {
		if _, err := DecodeChunk([]byte(bad)); err == nil {
			t.Fatal("accepted malformed chunk")
		}
	}
	if _, err := DecodeManifest(bytes.Repeat([]byte{' '}, MaxManifestBytes+1)); err != ErrLimit {
		t.Fatal("manifest raw cap")
	}
	if _, err := DecodeChunk(bytes.Repeat([]byte{' '}, MaxChunkBytes+1)); err != ErrLimit {
		t.Fatal("chunk raw cap")
	}
}
func TestTypedIntegerAndChunkLimitRejection(t *testing.T) {
	m, c := buildFixture(t, 1)
	changes := []func(*Manifest){
		func(m *Manifest) { m.ObservedCount = ^uint64(0) },
		func(m *Manifest) { m.InstalledCount = ^uint64(0) },
		func(m *Manifest) { m.ChunkCount = ^uint32(0) },
		func(m *Manifest) { m.CanonicalRowBytes = ^uint64(0) },
		func(m *Manifest) { m.ObservedCount = 0 },
		func(m *Manifest) { m.ChunkCount = 0 },
		func(m *Manifest) { m.DurationMS = -1 },
		func(m *Manifest) { m.DurationMS = 1 << 53 },
	}
	for _, change := range changes {
		bad := cloneManifest(m)
		change(&bad)
		if ValidateManifest(bad) == nil {
			t.Fatal("accepted integer cross-field error")
		}
	}
	for _, change := range []func(*Chunk){
		func(c *Chunk) { c.RowOffset = ^uint64(0) },
		func(c *Chunk) { c.ChunkCount = ^uint32(0) },
		func(c *Chunk) { c.Ordinal = ^uint32(0) },
		func(c *Chunk) { c.Items = nil },
		func(c *Chunk) { c.Items = make([]linuxpackages.PackageRow, 129) },
	} {
		bad := cloneChunk(c[0])
		change(&bad)
		rehash(&bad)
		if ValidateChunk(bad) == nil {
			t.Fatal("accepted typed bad chunk")
		}
	}
}

func FuzzStrictDecoders(f *testing.F) {
	m, c, _ := Build(context.Background(), sourceFixture(2), nil)
	mb, _ := json.Marshal(m)
	cb, _ := json.Marshal(c[0])
	f.Add(mb)
	f.Add(cb)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if m, err := DecodeManifest(raw); err == nil {
			if ValidateManifest(m) != nil {
				t.Fatal("accepted invalid manifest")
			}
		}
		if c, err := DecodeChunk(raw); err == nil {
			if ValidateChunk(c) != nil {
				t.Fatal("accepted invalid chunk")
			}
		}
	})
}
