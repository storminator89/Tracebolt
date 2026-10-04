package linuxpackages

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// Decode enforces the raw byte bound, exact required member names and types,
// duplicate rejection at every depth, then typed/canonical validation. It never
// returns a partially decoded snapshot. It accepts no provenance/target fields.
func Decode(raw []byte) (Snapshot, error) {
	if len(raw) > MaxSnapshotBytes {
		return Snapshot{}, ErrSnapshotLimit
	}
	if !utf8.Valid(raw) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readJSONValue(d, 0)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if _, err := d.Token(); err != io.EOF || !snapshotJSONShape(value) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := Validate(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

func readJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 6 {
		return nil, ErrInvalidSnapshot
	}
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	if delimiter, ok := t.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := make(map[string]any)
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok {
					return nil, ErrInvalidSnapshot
				}
				if _, exists := object[key]; exists {
					return nil, ErrInvalidSnapshot
				}
				v, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = v
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, ErrInvalidSnapshot
			}
			return object, nil
		case '[':
			array := []any{}
			for d.More() {
				v, err := readJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, v)
				if len(array) > MaxExportRows {
					return nil, ErrInvalidSnapshot
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, ErrInvalidSnapshot
			}
			return array, nil
		default:
			return nil, ErrInvalidSnapshot
		}
	}
	return t, nil
}

func exactObject(value any, keys ...string) (map[string]any, bool) {
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

func snapshotJSONShape(value any) bool {
	s, ok := exactObject(value, "schemaVersion", "scope", "generationId", "collectedAt", "durationMs", "release", "inventory")
	if !ok || !stringsOnly(s, "schemaVersion", "scope", "generationId", "collectedAt") || !integerJSON(s["durationMs"], false) {
		return false
	}
	if !strings.HasSuffix(s["collectedAt"].(string), "Z") {
		return false
	}
	r, ok := exactObject(s["release"], "quality", "reason", "fields")
	if !ok || !stringsOnly(r, "quality", "reason") {
		return false
	}
	f, ok := exactObject(r["fields"], "id", "versionId", "versionCodename")
	if !ok {
		return false
	}
	for _, v := range f {
		if _, ok := v.(string); v != nil && !ok {
			return false
		}
	}
	i, ok := exactObject(s["inventory"], "quality", "reason", "complete", "truncated", "countExact", "observedCount", "installedCount", "items")
	if !ok || !stringsOnly(i, "quality", "reason") || !integerJSON(i["observedCount"], true) || !integerJSON(i["installedCount"], true) {
		return false
	}
	for _, key := range []string{"complete", "truncated", "countExact"} {
		if _, ok := i[key].(bool); !ok {
			return false
		}
	}
	items, ok := i["items"].([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		keys := []string{"name", "version", "architecture", "sourcePackage", "sourceVersion", "sourceMapping", "installState"}
		p, ok := exactObject(item, keys...)
		if !ok || !stringsOnly(p, keys...) {
			return false
		}
	}
	return true
}

func stringsOnly(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := m[key].(string); !ok {
			return false
		}
	}
	return true
}

func integerJSON(value any, nullable bool) bool {
	if value == nil {
		return nullable
	}
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	text := number.String()
	if text == "" {
		return false
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
