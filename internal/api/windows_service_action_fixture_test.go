package api

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/windowsaction"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The checked-in interop fixture is actual bounded operator HTTP output. Every
// identity, key and native result here is synthetic; no envelope is exported.
func TestWindowsServiceActionAPIGoldenInterop(t *testing.T) {
	type scenario struct {
		Operation string          `json:"operation"`
		Preview   json.RawMessage `json:"preview"`
		Approved  json.RawMessage `json:"approved"`
		Complete  json.RawMessage `json:"complete"`
	}
	all := struct {
		Version  string     `json:"version"`
		ActorID  string     `json:"actorId"`
		DeviceID string     `json:"deviceId"`
		Cases    []scenario `json:"cases"`
	}{"tracebolt.windows-service-action-interop.v1", namedActorID, namedDeviceID, []scenario{}}
	for _, op := range []string{"start", "stop", "restart"} {
		o, f, csrf := windowsActionOperator(t)
		f.at = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
		f.record.ClockFloor = f.at
		f.record.Capabilities.CapturedAt = f.at.Unix()
		base := "/api/devices/" + namedDeviceID + "/windows-service-actions"
		call := func(method, path string, input any) json.RawMessage {
			t.Helper()
			r, v := o.call(t, method, path, input, csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(path, r.StatusCode, v)
			}
			raw, e := json.Marshal(v)
			if e != nil || bytes.Contains(raw, []byte(`"envelope"`)) {
				t.Fatal("unsafe fixture output", e)
			}
			return raw
		}
		c := scenario{Operation: op, Preview: call("POST", base+"/preview", map[string]string{"target": "FixtureService", "operation": op})}
		p := f.record.Preview
		c.Approved = call("POST", base+"/approve", map[string]string{"previewId": p.ID, "previewDigest": p.Digest})
		j := f.record.Jobs[0]
		if _, e := f.record.Claim(j.Identity(), f.at); e != nil {
			t.Fatal(e)
		}
		result := windowsaction.Result{Version: windowsaction.ResultVersion, Identity: j.Identity(), Operation: op, Target: "FixtureService", Deadline: j.Deadline().Unix(), Phase: "complete", Outcome: "running-observed", LastObservedState: 4, Observations: 4}
		if op != "start" {
			result.StopAttempted = true
			result.StopRequested = true
			result.StoppedObserved = true
		}
		if op != "stop" {
			result.StartAttempted = true
			result.StartRequested = true
			result.RunningObserved = true
		} else {
			result.Outcome = "stopped-observed"
			result.LastObservedState = 1
		}
		if e := f.record.Accept(result); e != nil {
			t.Fatal(e)
		}
		c.Complete = call("GET", base, nil)
		all.Cases = append(all.Cases, c)
	}
	raw, e := json.MarshalIndent(all, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-service-action-view.json")
	if os.Getenv("TRACEBOLT_UPDATE_WINDOWS_ACTION_FIXTURE") == "1" {
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	expected, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, expected) {
		t.Fatal("operator interop fixture changed; explicitly regenerate and verify its UI contract", e)
	}
}
