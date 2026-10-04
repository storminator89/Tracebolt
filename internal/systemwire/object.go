package systemwire

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return nil, ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, ErrContract
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] || out[k] != nil {
			return nil, ErrContract
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrContract
		}
		out[k] = value
	}
	if _, e = d.Token(); e != nil {
		return nil, ErrContract
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrContract
	}
	if len(out) != len(keys) {
		return nil, ErrContract
	}
	return out, nil
}
