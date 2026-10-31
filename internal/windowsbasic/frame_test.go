package windowsbasic

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const fixture = `{"schemaVersion":"tracebolt.agent-telemetry.windows-basic.v1","sequence":1,"collectedAt":"2026-10-31T12:00:00Z","cpuPercent":12.5,"physicalMemoryPercent":50,"systemVolumeUsedPercent":75,"uptimeSeconds":3600}`

var captured = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func changed(t *testing.T, key, value string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &object); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(object, key)
	} else {
		object[key] = json.RawMessage(value)
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOnlyFourMeasurementsAndProtocolMetadata(t *testing.T) {
	raw := []byte(fixture)
	before := bytes.Clone(raw)
	f, err := Decode(raw, captured)
	if err != nil || f.SchemaVersion != FrameVersion || f.Sequence != 1 || !f.CollectedAt.Equal(captured) || f.CPUPercent == nil || *f.CPUPercent != 12.5 || f.PhysicalMemoryPercent == nil || *f.PhysicalMemoryPercent != 50 || f.SystemVolumeUsedPercent == nil || *f.SystemVolumeUsedPercent != 75 || f.UptimeSeconds == nil || *f.UptimeSeconds != 3600 || !bytes.Equal(before, raw) {
		t.Fatal("minimal frame changed, expanded or mutated")
	}
	for _, field := range []string{"cpuPercent", "physicalMemoryPercent", "systemVolumeUsedPercent", "uptimeSeconds"} {
		f, err := Decode(changed(t, field, "null"), captured)
		if err != nil {
			t.Fatal("unavailable measurement rejected", field)
		}
		var v map[string]json.RawMessage
		encoded, _ := json.Marshal(f)
		_ = json.Unmarshal(encoded, &v)
		if string(v[field]) != "null" {
			t.Fatal("unavailable became zero", field)
		}
		if _, err = Decode(changed(t, field, "0"), captured); err != nil {
			t.Fatal("actual zero must remain distinct from unavailable", field)
		}
	}
	allNull := []byte(`{"schemaVersion":"tracebolt.agent-telemetry.windows-basic.v1","sequence":1,"collectedAt":"2026-10-31T12:00:00Z","cpuPercent":null,"physicalMemoryPercent":null,"systemVolumeUsedPercent":null,"uptimeSeconds":null}`)
	if _, err = Decode(allNull, captured); err != nil {
		t.Fatal("a contact with unavailable measurements must not imply zero health")
	}
}

func TestStrictClosedShapeRejectsClaimedAuthorityAndEveryExpandedSection(t *testing.T) {
	for _, field := range []string{
		"agentId", "deviceId", "managerInstanceId", "collectionProfile", "profile", "platform", "agentVersion", "agentType", "capabilities", "credential", "certificateHash",
		"observation", "hostname", "ip", "processes", "services", "software", "network", "logs", "actions", "operational", "packages",
		"windowsInventory", "windowsEvents", "windowsVolumes", "windowsProcessMetrics", "windowsNetwork", "windowsServiceStartup", "windowsUpdates", "windowsAdapterContext", "windowsPatchContext", "windowsSecurityPosture", "windowsSessionContext", "windowsHardwareContext", "windowsStorageContext", "windowsSecurityCoverage", "windowsResourceContext", "windowsStorageIO", "scope", "quality", "source", "tags", "evidence", "unknown",
	} {
		t.Run(field, func(t *testing.T) {
			if _, err := Decode(changed(t, field, `{"enabled":true}`), captured); !errors.Is(err, ErrFrame) {
				t.Fatal("client metadata expanded the minimal schema")
			}
		})
	}
	for field := range fields {
		t.Run("required/"+field, func(t *testing.T) {
			if _, err := Decode(changed(t, field, ""), captured); !errors.Is(err, ErrFrame) {
				t.Fatal("missing field admitted")
			}
		})
		// Escaped duplicate keys must not bypass the first occurrence either.
		duplicate := strings.TrimSuffix(fixture, "}") + `,"` + field + `":null}`
		if _, err := Decode([]byte(duplicate), captured); !errors.Is(err, ErrFrame) {
			t.Fatal("duplicate field admitted", field)
		}
	}
	for _, raw := range []string{
		strings.TrimSuffix(fixture, "}") + `,"\u0073equence":1}`,
		strings.Replace(fixture, `"sequence"`, `"Sequence"`, 1),
		fixture + `{}`, fixture + `null`, `[` + fixture + `]`, `null`, `{}`, ``,
		strings.Repeat(" ", MaxFrameBytes) + fixture,
	} {
		if _, err := Decode([]byte(raw), captured); !errors.Is(err, ErrFrame) {
			t.Fatal("invalid JSON/framing admitted")
		}
	}
	if _, err := Decode(append([]byte(fixture), 0xff), captured); !errors.Is(err, ErrFrame) {
		t.Fatal("invalid UTF-8 admitted")
	}
}

func TestScalarAndTimeBoundaries(t *testing.T) {
	for field, badValues := range map[string][]string{
		"schemaVersion":           {`null`, `"tracebolt.agent-telemetry.windows.v1"`, `"tracebolt.agent-telemetry.v1"`, `1`, `{}`, `[]`},
		"sequence":                {`null`, `0`, `-1`, `1.5`, `1e0`, `9007199254740992`, `18446744073709551616`, `"1"`, `{}`, `[]`},
		"collectedAt":             {`null`, `0`, `"2026-10-31T12:00:00+00:00"`, `"2026-10-31T12:00:00.0Z"`, `"0001-01-01T00:00:00Z"`, `"1970-01-01T00:00:00Z"`, `"not-a-time"`},
		"cpuPercent":              {`-0.01`, `100.01`, `1e309`, `"50"`, `true`, `{}`, `[]`},
		"physicalMemoryPercent":   {`-1`, `101`, `"0"`, `false`, `{}`, `[]`},
		"systemVolumeUsedPercent": {`-1`, `101`, `"0"`, `false`, `{}`, `[]`},
		"uptimeSeconds":           {`-1`, `1.5`, `1e0`, `9007199254740992`, `"3600"`, `false`, `{}`, `[]`},
	} {
		for _, value := range badValues {
			t.Run(field+"/"+value, func(t *testing.T) {
				f, err := Decode(changed(t, field, value), captured)
				if !errors.Is(err, ErrFrame) || f != (Frame{}) {
					t.Fatal("invalid scalar admitted or partial frame leaked")
				}
			})
		}
	}
	for _, test := range []struct {
		now  time.Time
		want error
	}{
		{captured.Add(SampleMaxAge), nil},
		{captured.Add(SampleMaxAge + time.Nanosecond), ErrStale},
		{captured.Add(-AllowedSkew), nil},
		{captured.Add(-AllowedSkew - time.Nanosecond), ErrStale},
		{time.Time{}, ErrFrame},
		{time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), ErrFrame},
	} {
		if _, err := Decode([]byte(fixture), test.now); !errors.Is(err, test.want) {
			t.Fatal("time boundary changed", test.now, err)
		}
	}
	for _, field := range []string{"cpuPercent", "physicalMemoryPercent", "systemVolumeUsedPercent"} {
		if _, err := Decode(changed(t, field, "100"), captured); err != nil {
			t.Fatal("inclusive percentage bound rejected")
		}
	}
	for _, field := range []string{"sequence", "uptimeSeconds"} {
		if _, err := Decode(changed(t, field, "9007199254740991"), captured); err != nil {
			t.Fatal("inclusive safe-integer bound rejected")
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(fixture))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"sequence":1,"sequence":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := Decode(raw, captured)
		if err != nil {
			if frame != (Frame{}) {
				t.Fatal("partial invalid frame leaked")
			}
			return
		}
		encoded, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(encoded, captured); err != nil {
			t.Fatal("successful parse cannot reproduce the same contract")
		}
	})
}
