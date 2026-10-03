package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"localrmm/internal/model"
)

func TestOneJSONObservation(t *testing.T) {
	for _, args := range [][]string{nil, {"--once"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("code %d: %s", code, stderr.String())
		}
		decoder := json.NewDecoder(&stdout)
		var device model.Device
		if err := decoder.Decode(&device); err != nil {
			t.Fatal(err)
		}
		if device.ID != "sandbox-local" || device.Status != "unknown" || device.Synthetic {
			t.Fatalf("wrong sample: %+v", device)
		}
		if err := decoder.Decode(&device); err != io.EOF {
			t.Fatalf("expected exactly one JSON value, got %v", err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("unexpected diagnostic: %s", stderr.String())
		}
	}
}

func TestRejectOtherModesAndTargets(t *testing.T) {
	for _, args := range [][]string{{"--once=false"}, {"--server", "https://example.invalid"}, {"/etc/passwd"}, {"--path=/etc/passwd"}, {"--interval=1s"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("args %v: code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Errorf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("fixture writer failure") }

func TestOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, brokenWriter{}, &stderr); code != 1 || stderr.Len() == 0 {
		t.Errorf("code=%d stderr=%s", code, stderr.String())
	}
}
