package restartgate

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/windowsservice"
)

// ValidateCLI accepts one exact production result, including explicit false
// fields. StateRetained is syntax only; it never proves retained state. Duplicate
// keys and trailing records are rejected before decoding typed values.
func ValidateCLI(raw []byte, exitCode int, rejection bool) error {
	if len(raw) == 0 || len(raw) > OutputLimit {
		return ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return ErrRejected
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return ErrRejected
		}
		key, ok := token.(string)
		if !ok {
			return ErrRejected
		}
		if _, exists := fields[key]; exists {
			return ErrRejected
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrRejected
		}
		fields[key] = value
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') {
		return ErrRejected
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrRejected
	}
	keys := []string{"outcome", "phase", "stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved", "observations", "stateRetained"}
	if !rejection {
		keys = append(keys, "lastObservedState")
	}
	if len(fields) != len(keys) {
		return ErrRejected
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrRejected
		}
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	var r windowsservice.RestartResult
	if typed.Decode(&r) != nil || !r.StateRetained {
		return ErrRejected
	}
	if rejection {
		if exitCode != 1 || r.Outcome != "not-requested" || r.Phase != "receipt" || r.StopAttempted || r.StopRequested || r.StoppedObserved || r.StartAttempted || r.StartRequested || r.RunningObserved || r.Observations != 0 || r.LastObservedState != 0 {
			return ErrRejected
		}
	} else {
		if exitCode != 0 || r.Outcome != "running-observed" || r.Phase != "complete" || !r.StopAttempted || !r.StopRequested || !r.StoppedObserved || !r.StartAttempted || !r.StartRequested || !r.RunningObserved || r.Observations < 6 || r.Observations > 184 || r.LastObservedState != windowsservice.Running {
			return ErrRejected
		}
	}
	return nil
}
