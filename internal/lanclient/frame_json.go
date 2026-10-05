package lanclient

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Pending bytes are never normalized: reject ambiguity before typed validation.
func rejectDuplicateJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 20 {
			return ErrState
		}
		token, err := d.Token()
		if err != nil {
			return ErrState
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrState
				}
				seen[name] = true
				if value(depth+1) != nil {
					return ErrState
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrState
			}
		case '[':
			for d.More() {
				if value(depth+1) != nil {
					return ErrState
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrState
			}
		default:
			return ErrState
		}
		return nil
	}
	if value(0) != nil {
		return ErrState
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrState
	}
	return nil
}

// Operational metadata requires every declared field, including false/zero values.
func exactOperationalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if exactShape(d, reflect.TypeOf(operational.Snapshot{}), 0) != nil {
		return ErrState
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrState
	}
	return nil
}
func exactShape(d *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 12 {
		return ErrState
	}
	token, err := d.Token()
	if err != nil {
		return ErrState
	}
	if typ.Kind() == reflect.Pointer {
		if token == nil {
			return nil
		}
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(time.Time{}) {
		if _, ok := token.(string); !ok {
			return ErrState
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrState
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			// Operator-owned expiry/provenance never extends endpoint wire fields.
			if typ == reflect.TypeOf(model.Evidence{}) && name == "collectionProfile" || typ == reflect.TypeOf(model.Device{}) && name == "agentCertificate" {
				continue
			}
			fields[name] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			field, known := fields[name]
			if err != nil || !ok || !known || seen[name] {
				return ErrState
			}
			seen[name] = true
			if exactShape(d, field, depth+1) != nil {
				return ErrState
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return ErrState
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return ErrState
		}
		for d.More() {
			if exactShape(d, typ.Elem(), depth+1) != nil {
				return ErrState
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrState
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return ErrState
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrState
		}
	case reflect.Int, reflect.Int64, reflect.Uint64, reflect.Float64:
		if _, ok := token.(json.Number); !ok {
			return ErrState
		}
	default:
		return ErrState
	}
	return nil
}

// The new schema requires all basic and contained fields without widening the
// existing pending-byte contracts. Evidence provenance remains server-only.
func exactPackageFrameJSON(raw []byte) error {
	// Match the ingress's bounded decoded strings, including JSON escapes that
	// the decoder would otherwise replace with U+FFFD. Old pending schemas keep
	// their historical decoding path.
	tokens := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := tokens.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrState
		}
		if s, ok := token.(string); ok && (len(s) > 4096 || strings.ContainsRune(s, utf8.RuneError)) {
			return ErrState
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if exactShape(d, reflect.TypeOf(frame{}), 0) != nil {
		return ErrState
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrState
	}
	return nil
}
