package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"
	"unicode/utf8"
)

// Go's default JSON decoder accepts case-insensitive names, missing fields and
// duplicate keys. All are inappropriate for this narrow ingestion contract.
func strictJSON(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if err := shape(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}
func walkJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("excessive depth")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("duplicate object key")
			}
			seen[s] = true
			if err = walkJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for d.More() {
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}

var timeType = reflect.TypeOf(time.Time{})

func shape(raw []byte, t reflect.Type) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		if t.Kind() == reflect.Pointer {
			return nil
		}
		return errors.New("unexpected null")
	}
	if t.Kind() == reflect.Pointer {
		return shape(raw, t.Elem())
	}
	if t == timeType {
		var s string
		return json.Unmarshal(raw, &s)
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		if len(obj) != t.NumField() {
			return errors.New("unexpected object fields")
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			v, ok := obj[f.Tag.Get("json")]
			if !ok {
				return errors.New("missing exact field")
			}
			if err := shape(v, f.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var a []json.RawMessage
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		for _, v := range a {
			if err := shape(v, t.Elem()); err != nil {
				return err
			}
		}
	default:
		v := reflect.New(t).Interface()
		return json.Unmarshal(raw, v)
	}
	return nil
}
