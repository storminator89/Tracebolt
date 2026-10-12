package windowssoftwaremanager

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// These purpose-specific configs contain an exact binding object or a bounded
// string array. lanconfig.StrictObject intentionally permits scalar-only LAN
// settings and cannot decode either shape. Keep duplicate, unknown, case-variant,
// null and trailing input rejection without relaxing the shared LAN decoder.
func strictManagerObject(raw []byte, out any) error {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return ErrConfiguration
	}
	allowed := map[string]bool{}
	for _, name := range []string{"version", "enabled", "binding", "privateKeyFile", "setupReceiptFile", "setupPlanDigest", "setupRegistrationDigest", "managerId", "deviceId", "incarnationDigest", "executorId", "executorKeyId", "grantId", "keyId", "configFiles"} {
		allowed[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 3 {
			return ErrConfiguration
		}
		token, e := d.Token()
		if e != nil || token == nil {
			return ErrConfiguration
		}
		delim, compound := token.(json.Delim)
		if !compound {
			if depth == 0 {
				return ErrConfiguration
			}
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, e := d.Token()
				key, ok := token.(string)
				if e != nil || !ok || !allowed[key] || seen[key] {
					return ErrConfiguration
				}
				seen[key] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrConfiguration
			}
		case '[':
			if depth == 0 {
				return ErrConfiguration
			}
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrConfiguration
			}
		default:
			return ErrConfiguration
		}
		return nil
	}
	if value(0) != nil {
		return ErrConfiguration
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrConfiguration
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrConfiguration
	}
	return nil
}
