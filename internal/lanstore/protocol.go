package lanstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/bundle"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const FrameVersion = "tracebolt.agent-telemetry.v1"
const MaxFrameBytes = 72 * 1024
const SampleMaxAge = 2 * time.Minute
const AllowedClockSkew = 30 * time.Second

var ErrFrame = errors.New("agent telemetry frame is invalid")
var ErrStale = errors.New("agent observation is stale or future-dated")

type Frame struct {
	SchemaVersion string        `json:"schemaVersion"`
	Sequence      uint64        `json:"sequence"`
	Observation   bundle.Bundle `json:"observation"`
}

// ValidateFrame separates protocol version from application/agent build version.
// Identity in the embedded observation is only a fixed collector-role label;
// the ingress maps the authenticated certificate to a server-assigned AgentID.
func ValidateFrame(raw []byte, now time.Time) (Frame, error) {
	var frame Frame
	if len(raw) == 0 || len(raw) > MaxFrameBytes || !utf8.Valid(raw) {
		return frame, ErrFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readStrictValue(decoder, 0)
	if err != nil {
		return frame, ErrFrame
	}
	if _, err = decoder.Token(); err != io.EOF {
		return frame, ErrFrame
	}
	if !shape(value, reflect.TypeOf(frame)) {
		return frame, ErrFrame
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(&frame) != nil {
		return frame, ErrFrame
	}
	b := frame.Observation
	if frame.SchemaVersion != FrameVersion || frame.Sequence == 0 || frame.Sequence > 1<<63-1 || b.SchemaVersion != bundle.SchemaVersion || b.Product != "Tracebolt" || b.Version == "" || len(b.Version) > 64 || b.Platform != b.Observation.Platform || b.Scope != "single-read-only-local-observation" {
		return frame, ErrFrame
	}
	if len(b.Architecture) == 0 || len(b.Architecture) > 32 || len(b.Privacy) > 16 {
		return frame, ErrFrame
	}
	if err = bundle.ValidateObservation(b.Observation); err != nil {
		return frame, ErrFrame
	}
	// Bound the actual incoming envelope, not a newly generated bundle whose
	// clock-dependent timestamp/default text could alter boundary acceptance.
	encoded, err := json.Marshal(b)
	if err != nil || len(encoded) > bundle.MaxBytes {
		return frame, ErrFrame
	}
	times := []time.Time{b.GeneratedAt, b.Observation.LastSeen, b.Observation.CPU.CollectedAt, b.Observation.Memory.CollectedAt, b.Observation.Disk.CollectedAt}
	for _, e := range b.Observation.Evidence {
		times = append(times, e.CollectedAt)
	}
	for _, at := range times {
		if at.IsZero() || now.Sub(at) > SampleMaxAge || at.Sub(now) > AllowedClockSkew {
			return frame, ErrStale
		}
		if at.After(b.GeneratedAt) {
			return frame, ErrFrame
		}
	}
	for _, at := range times[2:] {
		if at.After(b.Observation.LastSeen) {
			return frame, ErrFrame
		}
	}
	return frame, nil
}
func readStrictValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, ErrFrame
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			object := map[string]any{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || strings.ContainsRune(name, utf8.RuneError) {
					return nil, ErrFrame
				}
				if _, exists := object[name]; exists {
					return nil, ErrFrame
				}
				child, err := readStrictValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = child
				if len(object) > 64 {
					return nil, ErrFrame
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrFrame
			}
			return object, nil
		case '[':
			list := []any{}
			for d.More() {
				child, err := readStrictValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, child)
				if len(list) > 64 {
					return nil, ErrFrame
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrFrame
			}
			return list, nil
		default:
			return nil, ErrFrame
		}
	case string:
		if len(v) > 4096 || strings.ContainsRune(v, utf8.RuneError) {
			return nil, ErrFrame
		}
	}
	return token, nil
}
func shape(value any, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		if value == nil {
			return true
		}
		return shape(value, t.Elem())
	}
	if t == reflect.TypeOf(time.Time{}) {
		_, ok := value.(string)
		return ok
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		expected := 0
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			expected++
			child, exists := object[name]
			if !exists || !shape(child, field.Type) {
				return false
			}
		}
		return len(object) == expected
	case reflect.Slice:
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range list {
			if !shape(child, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Float32, reflect.Float64, reflect.Int, reflect.Int64, reflect.Uint64:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}
