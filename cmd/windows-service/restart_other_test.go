//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"localrmm/internal/windowsservice"
)

func TestRestartNativeCLIRejectsNonWindows(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run(context.Background(), []string{"--restart", "--apply"}, &out, &stderr)
	var got windowsservice.RestartResult
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || got.Outcome != "not-requested" || got.StopAttempted || got.StartAttempted {
		t.Fatal(code, out.String(), stderr.String())
	}
}
