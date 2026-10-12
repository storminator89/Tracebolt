package api

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/store"
)

// The outer request parser is intentionally scalar-oriented. These two bounded
// arrays need the same exact required/non-null/unique key discipline per row;
// in particular a missing or null inherit flag must never become a stop request.
func decodeFleetMonitoringRow(raw []byte, fields []string, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return store.ErrFleetMonitoringInvalid
	}
	expected := map[string]bool{}
	for _, key := range fields {
		expected[key] = true
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !expected[key] || seen[key] {
			return store.ErrFleetMonitoringInvalid
		}
		seen[key] = true
		var value json.RawMessage
		if err = d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return store.ErrFleetMonitoringInvalid
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != len(expected) {
		return store.ErrFleetMonitoringInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return store.ErrFleetMonitoringInvalid
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	return typed.Decode(out)
}

type fleetMonitoringSettingsInput []store.FleetMonitoringSetting

func (s *fleetMonitoringSettingsInput) UnmarshalJSON(raw []byte) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	if rows == nil || len(rows) > 3 {
		return store.ErrFleetMonitoringInvalid
	}
	result := make([]store.FleetMonitoringSetting, len(rows))
	for i, row := range rows {
		if err := decodeFleetMonitoringRow(row, []string{"metric", "enabled", "thresholdPercent"}, &result[i]); err != nil {
			return err
		}
	}
	*s = result
	return nil
}

type fleetMonitoringAssignmentInput struct {
	DeviceID       string `json:"deviceId"`
	Metric         string `json:"metric"`
	Revision       uint64 `json:"expectedRevision"`
	PolicyRevision uint64 `json:"expectedPolicyRevision"`
	Inherit        bool   `json:"inherit"`
}
type fleetMonitoringAssignmentsInput []fleetMonitoringAssignmentInput

func (s *fleetMonitoringAssignmentsInput) UnmarshalJSON(raw []byte) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	if rows == nil || len(rows) > 75 {
		return store.ErrFleetMonitoringInvalid
	}
	result := make([]fleetMonitoringAssignmentInput, len(rows))
	for i, row := range rows {
		if err := decodeFleetMonitoringRow(row, []string{"deviceId", "metric", "expectedRevision", "expectedPolicyRevision", "inherit"}, &result[i]); err != nil {
			return err
		}
	}
	*s = result
	return nil
}
