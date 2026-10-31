//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func quarantineCLITempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func invoke(t *testing.T, args ...string) (int, report, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out)
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal("invalid report", err)
	}
	if r.FreshnessVerified || r.AuthorityReleased {
		t.Fatal("marker inspection granted authority")
	}
	return code, r, out.String()
}

func TestRestoreQuarantineCLIExplicitMarkAndReadOnlyStatus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("CLI intentionally requires the existing nonroot runtime UID")
	}
	dir := quarantineCLITempDir(t)
	uid := strconv.Itoa(os.Geteuid())
	base := []string{"--state-directory", dir, "--runtime-uid", uid}
	if code, r, _ := invoke(t, append([]string{"status"}, base...)...); code != 0 || (r.MarkerPresent == nil || *r.MarkerPresent) || r.Created || r.Code != "marker_absent_not_freshness_proof" {
		t.Fatal("invalid status", code, r)
	}
	if code, _, _ := invoke(t, append([]string{"mark"}, base...)...); code == 0 {
		t.Fatal("mark omitted explicit acknowledgement")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("inspection or failed acknowledgement wrote state")
	}
	mark := append(append([]string{"mark"}, base...), "--ack-stopped-writers")
	if code, r, _ := invoke(t, mark...); code != 0 || !r.Created || (r.MarkerPresent == nil || !*r.MarkerPresent) {
		t.Fatal("mark not confirmed", code, r)
	}
	if code, r, _ := invoke(t, mark...); code != 0 || r.Created || (r.MarkerPresent == nil || !*r.MarkerPresent) {
		t.Fatal("repeat mark changed state", code, r)
	}
	if code, r, _ := invoke(t, append([]string{"status"}, base...)...); code != 0 || r.Created || (r.MarkerPresent == nil || !*r.MarkerPresent) {
		t.Fatal("status lost quarantine", code, r)
	}
}

func TestRestoreQuarantineCLIMissingPathAndSecretRedaction(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("CLI intentionally requires the existing nonroot runtime UID")
	}
	missing := filepath.Join(t.TempDir(), "missing-secret-marker")
	if code, _, out := invoke(t, "status", "--state-directory", missing, "--runtime-uid", strconv.Itoa(os.Geteuid())); code == 0 || strings.Contains(out, missing) {
		t.Fatal("missing target accepted or echoed")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("missing target created")
	}
	for _, args := range [][]string{{"release"}, {"reset"}, {"mark", "--unknown=secret-argument"}, {"status", "secret-argument"}} {
		if code, _, out := invoke(t, args...); code == 0 || strings.Contains(out, "secret-argument") {
			t.Fatal("invalid arguments accepted or leaked")
		}
	}
}

func TestRestoreQuarantineCLIRejectsWrongUIDWithoutWriting(t *testing.T) {
	dir := quarantineCLITempDir(t)
	code, r, _ := invoke(t, "mark", "--state-directory", dir, "--runtime-uid", strconv.Itoa(os.Geteuid()+1), "--ack-stopped-writers")
	if code == 0 || r.Code != "runtime_uid_rejected" || r.MarkerPresent != nil || r.Created {
		t.Fatal("wrong UID accepted or uncertainty misreported", code, r)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrong UID wrote state", err)
	}
}
