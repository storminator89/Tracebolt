//go:build windows

package windowsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"strings"
	"testing"
)

func TestKnownFolderProbeChild(t *testing.T) {
	if os.Getenv(knownFolderProbeMode) != "child" {
		t.Skip("read-only probe child only")
	}
	// Parent expectations are public-root hashes sent only through an anonymous
	// pipe. Neither paths nor hashes are emitted or persisted.
	var expected [64]byte
	if _, err := io.ReadFull(os.Stdin, expected[:]); err != nil {
		os.Exit(2)
	}
	var extra [1]byte
	if n, err := os.Stdin.Read(extra[:]); n != 0 || err != io.EOF {
		os.Exit(2)
	}
	pf, pfErr := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	pd, pdErr := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	pfHash, pdHash := sha256.Sum256([]byte(pf)), sha256.Sum256([]byte(pd))
	result := knownFolderObservation{knownFolderCategory(pf, pfErr), knownFolderCategory(pd, pdErr), pfErr == nil && bytes.Equal(pfHash[:], expected[:32]), pdErr == nil && bytes.Equal(pdHash[:], expected[32:])}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestKnownFolderRestrictedEnvironment(t *testing.T) {
	if os.Getenv(knownFolderProbeMode) != "parent" {
		t.Skip("read-only KnownFolder probe is opt-in")
	}
	pf, pfErr := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	pd, pdErr := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	if knownFolderCategory(pf, pfErr) != "valid" || knownFolderCategory(pd, pdErr) != "valid" {
		t.Fatal("parent KnownFolders unavailable")
	}
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal("system directory unavailable")
	}
	drive, err := knownFolderProbeDrive(root)
	if err != nil {
		t.Fatal("system directory invalid")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("probe executable unavailable")
	}
	pfHash, pdHash := sha256.Sum256([]byte(pf)), sha256.Sum256([]byte(pd))
	expected := append(pfHash[:], pdHash[:]...)
	// Exactly the current fresh child's OS allowlist. Public gate metadata has
	// no KnownFolder role and is deliberately absent from this non-gate probe.
	baseline := []string{}
	for _, key := range []string{"SystemRoot", "WINDIR", "COMPUTERNAME"} {
		value := os.Getenv(key)
		if strings.ContainsRune(value, 0) {
			t.Fatal("invalid OS environment")
		}
		baseline = append(baseline, key+"="+value)
	}
	before, err := runKnownFolderProbe(exe, baseline, expected)
	if err != nil {
		t.Fatal("baseline probe incomplete")
	}
	after, err := runKnownFolderProbe(exe, append(append([]string{}, baseline...), "SystemDrive="+drive), expected)
	if err != nil {
		t.Fatal("SystemDrive probe incomplete")
	}
	// Observation does not insist on a failure on every Windows configuration.
	// A fix is supported only if baseline differs and the single addition restores
	// both strict validity and equality with the valid parent KnownFolder roots.
	t.Logf("baseline_pf=%s baseline_pd=%s baseline_pf_equal=%t baseline_pd_equal=%t systemdrive_pf=%s systemdrive_pd=%s systemdrive_pf_equal=%t systemdrive_pd_equal=%t", before.ProgramFiles, before.ProgramData, before.ProgramFilesEqual, before.ProgramDataEqual, after.ProgramFiles, after.ProgramData, after.ProgramFilesEqual, after.ProgramDataEqual)
}
