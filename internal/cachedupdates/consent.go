package cachedupdates

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// LocalConsent is an exact, explicitly acknowledged local opt-in declaration.
// SenderBinding must be obtained from the existing validated v3 material: its
// established binding covers transport/profile, manager origin, agent ID and
// current certificate fingerprint. This value is public metadata, not a secret
// or proof that an operating-system administrator actually consented.
// Reading/creating/protecting the declaration belongs to the runtime boundary;
// these pure functions cannot enable collection or establish file authority.
type LocalConsent struct {
	SchemaVersion    string `json:"schemaVersion"`
	ExtensionVersion string `json:"extensionVersion"`
	Scope            string `json:"scope"`
	SenderBinding    string `json:"senderBinding"`
	Acknowledged     bool   `json:"acknowledged"`
}

// DecodeLocalConsent requires every member, an exact version/scope and the
// current validated sender binding. Empty/absent input means no consent, never
// an implied opt-in. Neither a manager setting nor an unknown future version
// may stand in for this acknowledgement. It accepts no path or credentials.
func DecodeLocalConsent(raw []byte, expectedBinding string) (LocalConsent, error) {
	return decodeLocalConsent(raw, expectedBinding, ConsentVersion, SchemaVersion, Scope)
}
func decodeLocalConsent(raw []byte, expectedBinding, version, extension, scope string) (LocalConsent, error) {
	bad := func() (LocalConsent, error) { return LocalConsent{}, ErrInvalidInput }
	if len(raw) == 0 || len(raw) > MaxConsentBytes || !utf8.Valid(raw) || !validConsentBinding(expectedBinding) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readConsentObject(d)
	if e != nil {
		return bad()
	}
	if _, e = d.Token(); e != io.EOF {
		return bad()
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 5 {
		return bad()
	}
	expected := map[string]any{"schemaVersion": version, "extensionVersion": extension, "scope": scope, "senderBinding": expectedBinding, "acknowledged": true}
	for key, want := range expected {
		got, ok := m[key]
		if !ok {
			return bad()
		}
		switch value := want.(type) {
		case string:
			actual, ok := got.(string)
			if !ok || actual != value {
				return bad()
			}
		case bool:
			actual, ok := got.(bool)
			if !ok || actual != value {
				return bad()
			}
		default:
			return bad()
		}
	}
	return LocalConsent{version, extension, scope, expectedBinding, true}, nil
}

// EncodeLocalConsent constructs no acknowledgement on the caller's behalf.
// A caller must supply an already explicitly acknowledged declaration.
func EncodeLocalConsent(c LocalConsent, expectedBinding string) ([]byte, error) {
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalidInput
	}
	if _, e = DecodeLocalConsent(raw, expectedBinding); e != nil {
		return nil, e
	}
	return raw, nil
}
func validConsentBinding(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// The consent object contains only strings and one boolean. Reject duplicates,
// unknown members, composite values and trailing input before validation.
func readConsentObject(d *json.Decoder) (any, error) {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidInput
	}
	out := map[string]any{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrInvalidInput
		}
		if _, exists := out[key]; exists {
			return nil, ErrInvalidInput
		}
		switch key {
		case "schemaVersion", "extensionVersion", "scope", "senderBinding", "acknowledged":
		default:
			return nil, ErrInvalidInput
		}
		value, err := d.Token()
		if err != nil {
			return nil, ErrInvalidInput
		}
		switch value.(type) {
		case string, bool:
		default:
			return nil, ErrInvalidInput
		}
		out[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return nil, ErrInvalidInput
	}
	return out, nil
}
