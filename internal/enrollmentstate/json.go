package enrollmentstate

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeSnapshot rejects duplicate, case-aliased, unknown and missing fields,
// trailing values, invalid UTF-8, nulls, wrong types, excessive nesting and size.
// Decoding is for inspection only; this cannot restore private authority.
// The protected storage adapter uses the distinct trusted-ledger contract.
func DecodeSnapshot(raw []byte) (Snapshot, error) {
	var s Snapshot
	if strictDecode(raw, &s) != nil || ValidateSnapshot(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}

func EncodeSnapshot(s Snapshot) ([]byte, error) {
	if ValidateSnapshot(s) != nil {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(s)
	if err != nil || len(b) > MaxJSONBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

func DecodeCreateCommand(raw []byte) (CreateCommand, error) {
	var c CreateCommand
	if strictDecode(raw, &c) != nil || validateCreate(c) != nil {
		return CreateCommand{}, ErrInvalid
	}
	return c, nil
}
func DecodeClaimCommand(raw []byte) (ClaimCommand, error) {
	var c ClaimCommand
	if strictDecode(raw, &c) != nil || validateClaim(c) != nil {
		return ClaimCommand{}, ErrInvalid
	}
	return c, nil
}
func DecodeApproveCommand(raw []byte) (ApproveCommand, error) {
	var c ApproveCommand
	if strictDecode(raw, &c) != nil || validateApprove(c) != nil {
		return ApproveCommand{}, ErrInvalid
	}
	return c, nil
}
func DecodeIntentCommand(raw []byte) (IntentCommand, error) {
	var c IntentCommand
	if strictDecode(raw, &c) != nil || validateIntent(c) != nil {
		return IntentCommand{}, ErrInvalid
	}
	return c, nil
}
func DecodeControl(raw []byte) (Control, error) {
	var c Control
	if strictDecode(raw, &c) != nil || validateControl(c) != nil {
		return Control{}, ErrInvalid
	}
	return c, nil
}
func DecodeTerminalCommand(raw []byte) (TerminalCommand, error) {
	var c TerminalCommand
	if strictDecode(raw, &c) != nil || validateControl(c.Control) != nil || !terminal(c.State) {
		return TerminalCommand{}, ErrInvalid
	}
	return c, nil
}

func strictDecode(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxJSONBytes || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalid
	}
	if !shape(v, reflect.TypeOf(dst).Elem()) {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}

func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch v := t.(type) {
	case json.Delim:
		// Contracts contain fixed objects and scalars only, never arrays.
		if v != '{' {
			return nil, ErrInvalid
		}
		m := map[string]any{}
		for d.More() {
			t, err := d.Token()
			name, ok := t.(string)
			if err != nil || !ok || strings.ContainsRune(name, utf8.RuneError) || len(name) > 64 {
				return nil, ErrInvalid
			}
			if _, exists := m[name]; exists {
				return nil, ErrInvalid
			}
			child, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[name] = child
			if len(m) > 32 {
				return nil, ErrInvalid
			}
		}
		if t, err := d.Token(); err != nil || t != json.Delim('}') {
			return nil, ErrInvalid
		}
		return m, nil
	case string:
		if len(v) > 1024 || strings.ContainsRune(v, utf8.RuneError) {
			return nil, ErrInvalid
		}
	case nil:
		return nil, ErrInvalid
	}
	return t, nil
}

func shape(v any, t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Tag.Get("json")
			child, ok := m[name]
			if !ok || !shape(child, f.Type) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Int64, reflect.Uint64:
		_, ok := v.(json.Number)
		return ok
	}
	return false
}
