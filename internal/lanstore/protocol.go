package lanstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsvolumes"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const FrameVersion = "tracebolt.agent-telemetry.v1"
const FrameOperationalVersion = "tracebolt.agent-telemetry.v2"
const FramePackagesVersion = "tracebolt.agent-telemetry.v3"
const FrameWindowsCapabilitiesVersion = "tracebolt.agent-telemetry.windows.v3"
const FrameWindowsEventsVersion = "tracebolt.agent-telemetry.windows.v2"
const FrameWindowsInventoryVersion = "tracebolt.agent-telemetry.windows.v1"
const MaxPackageObservationBytes = 16 << 10
const MaxPackageOperationalBytes = operational.MaxPackageFrameSnapshotBytes
const MaxFrameBytes = 72 * 1024
const SampleMaxAge = 2 * time.Minute
const AllowedClockSkew = 30 * time.Second

var ErrFrame = errors.New("agent telemetry frame is invalid")
var ErrStale = errors.New("agent observation is stale or future-dated")

type Frame struct {
	SchemaVersion    string                       `json:"schemaVersion"`
	Sequence         uint64                       `json:"sequence"`
	Observation      bundle.Bundle                `json:"observation"`
	Operational      *operational.Snapshot        `json:"operational,omitempty"`
	Packages         *linuxpackages.Snapshot      `json:"packages,omitempty"`
	WindowsInventory *windowsmanaged.Snapshot     `json:"windowsInventory,omitempty"`
	WindowsEvents    *windowseventhealth.Snapshot `json:"windowsEvents,omitempty"`
	WindowsVolumes   *windowsvolumes.Snapshot     `json:"windowsVolumes,omitempty"`
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
	shapeType := reflect.TypeOf(frame)
	object, ok := value.(map[string]any)
	if !ok {
		return frame, ErrFrame
	}
	if object["schemaVersion"] == FrameVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion string        `json:"schemaVersion"`
			Sequence      uint64        `json:"sequence"`
			Observation   bundle.Bundle `json:"observation"`
		}{})
	}
	if object["schemaVersion"] == FrameOperationalVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion string                `json:"schemaVersion"`
			Sequence      uint64                `json:"sequence"`
			Observation   bundle.Bundle         `json:"observation"`
			Operational   *operational.Snapshot `json:"operational"`
		}{})
	}
	if object["schemaVersion"] == FramePackagesVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion string                  `json:"schemaVersion"`
			Sequence      uint64                  `json:"sequence"`
			Observation   bundle.Bundle           `json:"observation"`
			Operational   *operational.Snapshot   `json:"operational"`
			Packages      *linuxpackages.Snapshot `json:"packages"`
		}{})
	}
	if object["schemaVersion"] == FrameWindowsInventoryVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion    string                   `json:"schemaVersion"`
			Sequence         uint64                   `json:"sequence"`
			Observation      bundle.Bundle            `json:"observation"`
			WindowsInventory *windowsmanaged.Snapshot `json:"windowsInventory"`
		}{})
	}
	if object["schemaVersion"] == FrameWindowsEventsVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion    string                       `json:"schemaVersion"`
			Sequence         uint64                       `json:"sequence"`
			Observation      bundle.Bundle                `json:"observation"`
			WindowsInventory *windowsmanaged.Snapshot     `json:"windowsInventory"`
			WindowsEvents    *windowseventhealth.Snapshot `json:"windowsEvents"`
		}{})
	}
	if object["schemaVersion"] == FrameWindowsCapabilitiesVersion {
		shapeType = reflect.TypeOf(struct {
			SchemaVersion    string                       `json:"schemaVersion"`
			Sequence         uint64                       `json:"sequence"`
			Observation      bundle.Bundle                `json:"observation"`
			WindowsInventory *windowsmanaged.Snapshot     `json:"windowsInventory"`
			WindowsEvents    *windowseventhealth.Snapshot `json:"windowsEvents,omitempty"`
			WindowsVolumes   *windowsvolumes.Snapshot     `json:"windowsVolumes"`
		}{})
	}
	if object["schemaVersion"] == FrameWindowsCapabilitiesVersion {
		if _, exists := object["windowsEvents"]; !exists {
			shapeType = reflect.TypeOf(struct {
				SchemaVersion    string                   `json:"schemaVersion"`
				Sequence         uint64                   `json:"sequence"`
				Observation      bundle.Bundle            `json:"observation"`
				WindowsInventory *windowsmanaged.Snapshot `json:"windowsInventory"`
				WindowsVolumes   *windowsvolumes.Snapshot `json:"windowsVolumes"`
			}{})
		}
	}
	if !shape(value, shapeType) {
		return frame, ErrFrame
	}
	if object["schemaVersion"] == FrameOperationalVersion {
		var rawMembers map[string]json.RawMessage
		if json.Unmarshal(raw, &rawMembers) != nil || len(rawMembers["operational"]) > operational.MaxSnapshotBytes {
			return frame, ErrFrame
		}
	}
	if object["schemaVersion"] == FramePackagesVersion {
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || len(members["observation"]) > MaxPackageObservationBytes || len(members["operational"]) > MaxPackageOperationalBytes {
			return frame, ErrFrame
		}
		if _, err := linuxpackages.Decode(members["packages"]); err != nil {
			return frame, ErrFrame
		}
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if strict.Decode(&frame) != nil {
		return frame, ErrFrame
	}
	b := frame.Observation
	if (frame.SchemaVersion != FrameVersion && frame.SchemaVersion != FrameOperationalVersion && frame.SchemaVersion != FramePackagesVersion && frame.SchemaVersion != FrameWindowsInventoryVersion && frame.SchemaVersion != FrameWindowsEventsVersion && frame.SchemaVersion != FrameWindowsCapabilitiesVersion) || frame.Sequence == 0 || frame.Sequence > 1<<63-1 || b.SchemaVersion != bundle.SchemaVersion || b.Product != "Tracebolt" || b.Version == "" || len(b.Version) > 64 || b.Platform != b.Observation.Platform || b.Scope != "single-read-only-local-observation" {
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
	if frame.SchemaVersion == FrameVersion {
		if frame.Operational != nil || frame.Packages != nil || frame.WindowsInventory != nil || frame.WindowsEvents != nil || frame.WindowsVolumes != nil {
			return frame, ErrFrame
		}
	} else if frame.SchemaVersion == FrameWindowsInventoryVersion || frame.SchemaVersion == FrameWindowsEventsVersion || frame.SchemaVersion == FrameWindowsCapabilitiesVersion {
		if frame.Sequence > operational.MaxSafeInteger || frame.Operational != nil || frame.Packages != nil || frame.WindowsInventory == nil || b.Platform != "windows" || windowsmanaged.Validate(*frame.WindowsInventory) != nil || len(encoded) > MaxPackageObservationBytes {
			return frame, ErrFrame
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || len(members["observation"]) > MaxPackageObservationBytes {
			return frame, ErrFrame
		}
		if _, err := windowsmanaged.Decode(members["windowsInventory"]); err != nil {
			return frame, ErrFrame
		}
		if frame.SchemaVersion == FrameWindowsEventsVersion || frame.SchemaVersion == FrameWindowsCapabilitiesVersion && frame.WindowsEvents != nil {
			events, e := windowseventhealth.Decode(members["windowsEvents"])
			if e != nil || events.GenerationID != frame.WindowsInventory.GenerationID || events.CollectedAt.After(b.GeneratedAt) {
				return frame, ErrFrame
			}
			if now.Sub(events.CollectedAt) > SampleMaxAge || events.CollectedAt.Sub(now) > AllowedClockSkew {
				return frame, ErrStale
			}
		} else if frame.WindowsEvents != nil || len(members["windowsEvents"]) != 0 {
			return frame, ErrFrame
		}
		if frame.SchemaVersion == FrameWindowsCapabilitiesVersion {
			volumes, e := windowsvolumes.Decode(members["windowsVolumes"])
			if e != nil || volumes.GenerationID != frame.WindowsInventory.GenerationID || volumes.CollectedAt.After(b.GeneratedAt) {
				return frame, ErrFrame
			}
			if now.Sub(volumes.CollectedAt) > SampleMaxAge || volumes.CollectedAt.Sub(now) > AllowedClockSkew {
				return frame, ErrStale
			}
		} else if frame.WindowsVolumes != nil {
			return frame, ErrFrame
		}
		at := frame.WindowsInventory.CollectedAt
		if at.After(b.GeneratedAt) || at.After(b.Observation.LastSeen) {
			return frame, ErrFrame
		}
		if now.Sub(at) > SampleMaxAge || at.Sub(now) > AllowedClockSkew {
			return frame, ErrStale
		}
	} else {
		if frame.WindowsInventory != nil || frame.WindowsEvents != nil || frame.WindowsVolumes != nil {
			return frame, ErrFrame
		}
		if frame.SchemaVersion == FrameOperationalVersion && frame.Packages != nil {
			return frame, ErrFrame
		}
		op := frame.Operational
		if op == nil || frame.Sequence > operational.MaxSafeInteger || b.Platform != "linux" || operational.Validate(*op) != nil {
			return frame, ErrFrame
		}
		if op.CollectedAt.After(b.GeneratedAt) {
			return frame, ErrFrame
		}
		if now.Sub(op.CollectedAt) > SampleMaxAge || op.CollectedAt.Sub(now) > AllowedClockSkew {
			return frame, ErrStale
		}
	}
	if frame.SchemaVersion == FramePackagesVersion {
		p := frame.Packages
		if p == nil || linuxpackages.Validate(*p) != nil || p.GenerationID != frame.Operational.GenerationID || !p.CollectedAt.Equal(frame.Operational.CollectedAt) || len(encoded) > MaxPackageObservationBytes {
			return frame, ErrFrame
		}
		op, err := json.Marshal(frame.Operational)
		if err != nil || len(op) > MaxPackageOperationalBytes {
			return frame, ErrFrame
		}
		canonical, err := json.Marshal(frame)
		if err != nil || len(canonical) > MaxFrameBytes {
			return frame, ErrFrame
		}
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
				if len(list) > 256 {
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
			// Manager-owned expiry and evidence provenance are operator-only.
			// They do not extend the support-bundle-v1 wire contract.
			if t == reflect.TypeOf(model.Evidence{}) && name == "collectionProfile" || t == reflect.TypeOf(model.Device{}) && name == "agentCertificate" {
				if _, present := object[name]; present {
					return false
				}
				continue
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
	case reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}

// FrameMatchesCollectionProfile accepts only the profile from trusted durable
// identity state, never a profile claimed by the incoming payload itself.
func FrameMatchesCollectionProfile(frame Frame, profile string) bool {
	if (frame.WindowsInventory != nil || frame.WindowsEvents != nil || frame.WindowsVolumes != nil) && profile != windowsmanaged.CollectionProfile {
		return false
	}
	switch profile {
	case windowsmanaged.CollectionProfile:
		return (frame.SchemaVersion == FrameWindowsInventoryVersion && frame.WindowsEvents == nil && frame.WindowsVolumes == nil || frame.SchemaVersion == FrameWindowsEventsVersion && frame.WindowsEvents != nil && frame.WindowsVolumes == nil || frame.SchemaVersion == FrameWindowsCapabilitiesVersion && frame.WindowsVolumes != nil) && frame.WindowsInventory != nil && frame.WindowsInventory.CollectionProfile == profile && frame.Operational == nil && frame.Packages == nil && frame.Observation.Platform == "windows"
	case "basic-readonly-v1":
		return frame.SchemaVersion == FrameVersion && frame.Operational == nil && frame.Packages == nil
	case operational.CollectionProfile:
		return frame.SchemaVersion == FrameOperationalVersion && frame.Operational != nil && frame.Packages == nil && frame.Operational.CollectionProfile == profile && frame.Observation.Platform == "linux"
	case enrollmentcrypto.CollectionProfilePackages:
		return frame.SchemaVersion == FramePackagesVersion && frame.Operational != nil && frame.Packages != nil && frame.Operational.CollectionProfile == operational.CollectionProfile && frame.Observation.Platform == "linux"
	case enrollmentcrypto.CollectionProfileComplete:
		// Complete packages travel through the independent generation protocol;
		// periodic metrics retain the bounded operational schema without a second
		// truncated package observation or client-controlled profile downgrade.
		return frame.SchemaVersion == FrameOperationalVersion && frame.Operational != nil && frame.Packages == nil && frame.Operational.CollectionProfile == operational.CollectionProfile && frame.Observation.Platform == "linux"
	default:
		return false
	}
}
