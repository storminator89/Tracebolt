package updategeneration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictManifestDecoderRejectsAmbiguousShape(t *testing.T) {
	m, _ := built(t, 400)
	raw, _ := json.Marshal(m)
	for name, bad := range map[string][]byte{
		"unknown":          bytes.Replace(raw, []byte(`"scope":`), []byte(`"extra":true,"scope":`), 1),
		"duplicate":        bytes.Replace(raw, []byte(`"candidateCount":400`), []byte(`"candidateCount":400,"candidateCount":400`), 1),
		"missing":          bytes.Replace(raw, []byte(`"candidateCount":400,`), nil, 1),
		"nullable-count":   bytes.Replace(raw, []byte(`"candidateCount":400`), []byte(`"candidateCount":null`), 1),
		"fraction":         bytes.Replace(raw, []byte(`"candidateCount":400`), []byte(`"candidateCount":400.0`), 1),
		"exponent":         bytes.Replace(raw, []byte(`"candidateCount":400`), []byte(`"candidateCount":4e2`), 1),
		"alias":            bytes.Replace(raw, []byte(`"metadata"`), []byte(`"Metadata"`), 1),
		"nested-unknown":   bytes.Replace(raw, []byte(`"freshness":`), []byte(`"sourceUrl":"https://invalid.example","freshness":`), 1),
		"nested-duplicate": bytes.Replace(raw, []byte(`"freshness":"stale"`), []byte(`"freshness":"stale","freshness":"stale"`), 1),
		"scope-null":       bytes.Replace(raw, []byte(`"scope":"`+Scope+`"`), []byte(`"scope":null`), 1),
		"trailing":         append(bytes.Clone(raw), []byte(` {}`)...),
		"oversized":        append(bytes.Repeat([]byte(" "), MaxManifestBytes), raw...),
		"invalid-utf8":     append(bytes.Clone(raw), 0xff),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManifest(bad); err == nil {
				t.Fatal("ambiguous manifest accepted")
			}
		})
	}
}
func TestStrictChunkDecoderRejectsAmbiguousShapeAndOversize(t *testing.T) {
	_, chunks := built(t, 400)
	raw, _ := json.Marshal(chunks[0])
	for name, bad := range map[string][]byte{
		"unknown":   bytes.Replace(raw, []byte(`"ordinal":`), []byte(`"consent":true,"ordinal":`), 1),
		"duplicate": bytes.Replace(raw, []byte(`"ordinal":0`), []byte(`"ordinal":0,"ordinal":0`), 1),
		"missing":   bytes.Replace(raw, []byte(`"ordinal":0,`), nil, 1),
		"null":      bytes.Replace(raw, []byte(`"items":[`), []byte(`"items":null,"unexpected":[`), 1),
		"fraction":  bytes.Replace(raw, []byte(`"ordinal":0`), []byte(`"ordinal":0.0`), 1),
		"row-extra": bytes.Replace(raw, []byte(`"name":`), []byte(`"origin":"unverified","name":`), 1),
		"row-alias": bytes.Replace(raw, []byte(`"installedVersion":`), []byte(`"InstalledVersion":`), 1),
		"row-null":  bytes.Replace(raw, []byte(`"state":"held"`), []byte(`"state":null`), 1),
		"trailing":  append(bytes.Clone(raw), []byte(` []`)...),
		"oversized": append(bytes.Repeat([]byte(" "), MaxChunkBytes), raw...),
		"deep":      []byte(strings.Repeat(`[`, 20) + `0` + strings.Repeat(`]`, 20)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeChunk(bad); err == nil {
				t.Fatal("ambiguous chunk accepted")
			}
		})
	}
}
func FuzzManifest(f *testing.F) {
	m, _ := built(f, 3)
	raw, _ := json.Marshal(m)
	f.Add(raw)
	f.Add([]byte(`{"scope":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := DecodeManifest(raw)
		if err != nil {
			return
		}
		encoded, _ := json.Marshal(m)
		again, err := DecodeManifest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := ManifestDigest(m)
		b, _ := ManifestDigest(again)
		if a != b {
			t.Fatal("manifest roundtrip changed digest")
		}
	})
}
func FuzzChunk(f *testing.F) {
	_, chunks := built(f, 3)
	raw, _ := json.Marshal(chunks[0])
	f.Add(raw)
	f.Add([]byte(`{"items":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := DecodeChunk(raw)
		if err != nil {
			return
		}
		encoded, _ := json.Marshal(c)
		again, err := DecodeChunk(encoded)
		if err != nil || again.SHA256 != c.SHA256 {
			t.Fatal("chunk roundtrip", err)
		}
	})
}
