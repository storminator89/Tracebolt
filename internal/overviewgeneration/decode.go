package overviewgeneration

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

func strictValue(raw []byte, limit int) (any, error) {
	if len(raw) > limit {
		return nil, ErrLimit
	}
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}
func decodeTyped(raw []byte, limit int, out any) error {
	value, err := strictValue(raw, limit)
	if err != nil {
		return err
	}
	if !exactJSONType(value, reflect.TypeOf(out).Elem()) || json.Unmarshal(raw, out) != nil {
		return ErrInvalid
	}
	return nil
}
func DecodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := decodeTyped(raw, MaxManifestBytes, &m); err != nil {
		return Manifest{}, err
	}
	if err := ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func DecodeChunk(raw []byte) (Chunk, error) {
	var c Chunk
	if err := decodeTyped(raw, MaxChunkBytes, &c); err != nil {
		return Chunk{}, err
	}
	if err := ValidateChunk(c); err != nil {
		return Chunk{}, err
	}
	return c, nil
}
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}
func EncodeChunk(c Chunk) ([]byte, error) {
	if err := ValidateChunk(c); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				k, ok := key.(string)
				if err != nil || !ok {
					return nil, ErrInvalid
				}
				if _, ok = m[k]; ok {
					return nil, ErrInvalid
				}
				v, err := readJSON(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
				if len(m) > 32 {
					return nil, ErrInvalid
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := readJSON(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
				if len(a) > MaxGenerationRows {
					return nil, ErrInvalid
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	}
	return t, nil
}

var timeType = reflect.TypeOf(time.Time{})

func exactJSONType(v any, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		return v == nil || exactJSONType(v, t.Elem())
	}
	if v == nil {
		return false
	}
	if t == timeType {
		s, ok := v.(string)
		return ok && strings.HasSuffix(s, "Z")
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := f.Tag.Get("json")
			x, ok := m[key]
			if !ok || !exactJSONType(x, f.Type) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			_, ok := v.(string)
			return ok
		}
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !exactJSONType(x, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Bool:
		_, ok := v.(bool)
		return ok
	case reflect.Float64:
		_, ok := v.(json.Number)
		return ok
	case reflect.Int64, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		s := n.String()
		if s == "" {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	default:
		return false
	}
}
