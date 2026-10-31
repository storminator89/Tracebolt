package windowsbasic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"
	"unicode/utf8"
)

const (
	MaxFrameBytes = 2048
	// Safe integers preserve exact sequence/uptime values in the browser too.
	MaxSafeInteger = uint64(1<<53 - 1)
	SampleMaxAge   = 2 * time.Minute
	AllowedSkew    = 30 * time.Second
)

var ErrFrame = errors.New("Windows Basic metrics frame is invalid")
var ErrStale = errors.New("Windows Basic metrics frame is stale or future-dated")

// Frame has no sender-selected identity, profile, version, capabilities, labels,
// free text or inventory. Nil values mean unavailable, never zero or healthy.
// CPU is the observed processor group's GetSystemTimes percentage; memory is
// GlobalMemoryStatusEx physical memory; system volume is GetDiskFreeSpaceExW
// caller-quota used percentage. These semantics are fixed, not client labels.
// All seven fields are mandatory on the wire; the four measurements are nullable.
type Frame struct {
	SchemaVersion           string    `json:"schemaVersion"`
	Sequence                uint64    `json:"sequence"`
	CollectedAt             time.Time `json:"collectedAt"`
	CPUPercent              *float64  `json:"cpuPercent"`
	PhysicalMemoryPercent   *float64  `json:"physicalMemoryPercent"`
	SystemVolumeUsedPercent *float64  `json:"systemVolumeUsedPercent"`
	UptimeSeconds           *uint64   `json:"uptimeSeconds"`
}

var fields = map[string]bool{
	"schemaVersion": true, "sequence": true, "collectedAt": true,
	"cpuPercent": true, "physicalMemoryPercent": true,
	"systemVolumeUsedPercent": true, "uptimeSeconds": true,
}

// Decode enforces a bounded, duplicate-free, exact, flat JSON object. It validates
// data shape/time only, never authorizes an identity or advances a replay floor.
func Decode(raw []byte, now time.Time) (Frame, error) {
	var zero Frame
	if len(raw) == 0 || len(raw) > MaxFrameBytes || !utf8.Valid(raw) {
		return zero, ErrFrame
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return zero, ErrFrame
	}
	seen := make(map[string]json.RawMessage, len(fields))
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !fields[key] {
			return zero, ErrFrame
		}
		if _, duplicate := seen[key]; duplicate {
			return zero, ErrFrame
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return zero, ErrFrame
		}
		seen[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return zero, ErrFrame
	}
	if _, err := d.Token(); err != io.EOF {
		return zero, ErrFrame
	}
	var frame Frame
	if json.Unmarshal(raw, &frame) != nil || frame.SchemaVersion != FrameVersion || frame.Sequence == 0 || frame.Sequence > MaxSafeInteger {
		return zero, ErrFrame
	}
	// Canonical whole-second UTC timestamps avoid string/offset aliases. A null
	// timestamp and zero/out-of-contract clocks must not produce fresh evidence.
	var capture string
	if json.Unmarshal(seen["collectedAt"], &capture) != nil || capture != frame.CollectedAt.UTC().Format(time.RFC3339) || frame.CollectedAt.Unix() <= 0 || now.Unix() <= 0 || now.Year() > 9999 {
		return zero, ErrFrame
	}
	for _, value := range []*float64{frame.CPUPercent, frame.PhysicalMemoryPercent, frame.SystemVolumeUsedPercent} {
		if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 100) {
			return zero, ErrFrame
		}
	}
	if frame.UptimeSeconds != nil && *frame.UptimeSeconds > MaxSafeInteger {
		return zero, ErrFrame
	}
	if now.Sub(frame.CollectedAt) > SampleMaxAge || frame.CollectedAt.Sub(now) > AllowedSkew {
		return zero, ErrStale
	}
	return frame, nil
}
