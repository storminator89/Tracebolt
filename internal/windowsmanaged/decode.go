package windowsmanaged

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Decode rejects duplicate, missing, unknown, wrong-case and null members at
// every depth, fractional/exponent integers, non-UTC times and trailing data.
// Decoding never invokes a collector or refreshes any capture timestamp.
func Decode(raw []byte) (Snapshot, error) {
	if len(raw) > MaxSnapshotBytes {
		return Snapshot{}, ErrSnapshotLimit
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

func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 8 {
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
				if _, exists := m[k]; exists {
					return nil, ErrInvalidSnapshot
				}
				v, err := readJSON(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
				if len(m) > 16 {
					return nil, ErrInvalidSnapshot
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
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
				if len(a) > MaxProcessRows {
					return nil, ErrInvalidSnapshot
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
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
	if v == nil {
		return false
	}
	if t == timeType {
		s, ok := v.(string)
		if !ok || !strings.HasSuffix(s, "Z") {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, s)
		return err == nil && validTime(at) && at.Format(time.RFC3339Nano) == s
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			x, ok := m[f.Tag.Get("json")]
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
	case reflect.Int, reflect.Uint32:
		n, ok := v.(json.Number)
		if !ok || n.String() == "" {
			return false
		}
		for _, c := range n.String() {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}
