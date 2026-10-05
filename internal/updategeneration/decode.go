package updategeneration

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// DecodeManifest rejects unknown, duplicate, missing, null, wrongly typed and
// oversized wire data before typed validation. It never returns partial facts.
func DecodeManifest(raw []byte) (Manifest, error) {
	value, err := strictValue(raw, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	if !manifestShape(value) {
		return Manifest{}, ErrInvalid
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil {
		return Manifest{}, ErrInvalid
	}
	if err := ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func DecodeChunk(raw []byte) (Chunk, error) {
	value, err := strictValue(raw, MaxChunkBytes)
	if err != nil {
		return Chunk{}, err
	}
	if !chunkShape(value) {
		return Chunk{}, ErrInvalid
	}
	var c Chunk
	if json.Unmarshal(raw, &c) != nil {
		return Chunk{}, ErrInvalid
	}
	if err := ValidateChunk(c); err != nil {
		return Chunk{}, err
	}
	return c, nil
}
func strictValue(raw []byte, limit int) (any, error) {
	if len(raw) > limit {
		return nil, ErrLimit
	}
	if !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return value, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 6 {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || len(key) > 64 || len(m) >= 32 {
					return nil, ErrInvalid
				}
				if _, exists := m[key]; exists {
					return nil, ErrInvalid
				}
				value, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = value
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= MaxChunkRows {
					return nil, ErrInvalid
				}
				value, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, value)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	}
	if s, ok := t.(string); ok && len(s) > 1024 {
		return nil, ErrInvalid
	}
	return t, nil
}
func object(value any, keys ...string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return nil, false
		}
	}
	return m, true
}
func stringsOnly(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := m[key].(string); !ok {
			return false
		}
	}
	return true
}
func integersOnly(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		n, ok := m[key].(json.Number)
		if !ok {
			return false
		}
		s := n.String()
		if s == "" || len(s) > 20 {
			return false
		}
		for _, ch := range s {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
func manifestShape(value any) bool {
	m, ok := object(value, "schemaVersion", "scope", "generationId", "collectedAt", "durationMs", "release", "metadata", "comparisonCoverage", "comparisonReason", "installedCount", "checkedCount", "candidateCount", "heldCount", "unknownCount", "chunkCount", "canonicalRowBytes", "rowsSha256")
	if !ok || !stringsOnly(m, "schemaVersion", "scope", "generationId", "collectedAt", "comparisonCoverage", "comparisonReason", "rowsSha256") || !integersOnly(m, "durationMs", "installedCount", "checkedCount", "candidateCount", "heldCount", "unknownCount", "chunkCount", "canonicalRowBytes") || !strings.HasSuffix(m["collectedAt"].(string), "Z") {
		return false
	}
	release, ok := object(m["release"], "id", "versionId", "versionCodename")
	if !ok {
		return false
	}
	for _, value := range release {
		if _, ok := value.(string); value != nil && !ok {
			return false
		}
	}
	meta, ok := object(m["metadata"], "freshness", "oldestIndexModifiedAt", "ageSeconds", "ageBasis", "refresh")
	if !ok || !stringsOnly(meta, "freshness", "ageBasis", "refresh") {
		return false
	}
	if at := meta["oldestIndexModifiedAt"]; at != nil {
		value, ok := at.(string)
		if !ok || !strings.HasSuffix(value, "Z") {
			return false
		}
	}
	if meta["ageSeconds"] != nil && !integersOnly(meta, "ageSeconds") {
		return false
	}
	return true
}
func chunkShape(value any) bool {
	c, ok := object(value, "schemaVersion", "generationId", "manifestSha256", "ordinal", "chunkCount", "rowOffset", "previousSha256", "items", "sha256")
	if !ok || !stringsOnly(c, "schemaVersion", "generationId", "manifestSha256", "previousSha256", "sha256") ||
		!integersOnly(c, "ordinal", "chunkCount", "rowOffset") {
		return false
	}
	rows, ok := c["items"].([]any)
	if !ok {
		return false
	}
	for _, row := range rows {
		keys := []string{"name", "architecture", "installedVersion", "candidateVersion", "state", "installability"}
		p, ok := object(row, keys...)
		if !ok || !stringsOnly(p, keys...) {
			return false
		}
	}
	return true
}
