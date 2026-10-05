package cachedupdates

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// DecodeStrict requires every declared member, rejects unknown/duplicate keys at
// every depth, null nonnullable values, noninteger numbers and invalid UTF-8.
func DecodeStrict(raw []byte) (Snapshot, error) {
	if len(raw) > MaxSnapshotBytes {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if !utf8.Valid(raw) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if _, err = d.Token(); err != io.EOF || !exactJSONType(v, reflect.TypeOf(Snapshot{})) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	var s Snapshot
	if json.Unmarshal(raw, &s) != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := Validate(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
func Decode(raw []byte) (Snapshot, error) { return DecodeStrict(raw) }
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, ErrInvalidSnapshot
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
					return nil, ErrInvalidSnapshot
				}
				if _, ok = m[k]; ok {
					return nil, ErrInvalidSnapshot
				}
				v, err := readJSON(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
				if len(m) > 32 {
					return nil, ErrInvalidSnapshot
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalidSnapshot
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
				if len(a) > MaxRows {
					return nil, ErrInvalidSnapshot
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalidSnapshot
			}
			return a, nil
		default:
			return nil, ErrInvalidSnapshot
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
