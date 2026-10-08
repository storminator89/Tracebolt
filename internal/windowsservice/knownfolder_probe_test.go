package windowsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"
)

// This opt-in ordinary-CI probe only reads two KnownFolders in an owned child.
// No native acceptance tag, coordinator, service, identity, ACL or network call.
const knownFolderProbeMode = "TRACEBOLT_KNOWNFOLDER_PROBE"

type knownFolderObservation struct {
	ProgramFiles      string `json:"program_files"`
	ProgramData       string `json:"program_data"`
	ProgramFilesEqual bool   `json:"program_files_equal"`
	ProgramDataEqual  bool   `json:"program_data_equal"`
}

func knownFolderCategory(path string, err error) string {
	if err != nil {
		return "api_error"
	}
	_, err = layoutFromRoots(path, path)
	if err == nil {
		return "valid"
	}
	stage, _ := SetupDiagnostic(err)
	if stage == "service_layout_root" {
		return "unsafe_root"
	}
	return "unsafe_component"
}

type knownFolderProbeOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *knownFolderProbeOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 1024 {
		b.overflow = true
		return n, nil
	}
	if !b.overflow {
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func runKnownFolderProbe(exe string, env []string, expected []byte) (knownFolderObservation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestKnownFolderProbeChild$", "-test.count=1", "-test.timeout=8s")
	cmd.Env = append(append([]string{}, env...), knownFolderProbeMode+"=child", "GOTRACEBACK=none")
	cmd.Stdin = bytes.NewReader(expected)
	var out knownFolderProbeOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || out.overflow {
		return knownFolderObservation{}, errors.New("probe child failed")
	}
	return parseKnownFolderObservation(out.Bytes())
}

func parseKnownFolderObservation(raw []byte) (knownFolderObservation, error) {
	var result knownFolderObservation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&result) != nil || dec.Decode(new(any)) != io.EOF {
		return knownFolderObservation{}, errors.New("invalid probe output")
	}
	for _, value := range []string{result.ProgramFiles, result.ProgramData} {
		switch value {
		case "valid", "api_error", "unsafe_root", "unsafe_component":
		default:
			return knownFolderObservation{}, errors.New("invalid probe category")
		}
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) || (result.ProgramFilesEqual && result.ProgramFiles != "valid") || (result.ProgramDataEqual && result.ProgramData != "valid") {
		return knownFolderObservation{}, errors.New("noncanonical probe output")
	}
	return result, nil
}

func TestKnownFolderProbeDriveValidation(t *testing.T) {
	for _, value := range []string{"", `C:`, `C:\`, `C:Windows`, `\\server\Windows`, `%SystemRoot%`, `C:\..\Windows`, `C:\Windows.`, `C:\Windows `, `C:\Windows%bad%`, `C:\Windows*`, "C:\\Windows\x00"} {
		if _, err := SystemDriveFromWindowsDirectory(value); err == nil {
			t.Fatal("unsafe system directory accepted")
		}
	}
	for _, value := range []string{`C:\Windows`, `D:\WinNT`} {
		if drive, err := SystemDriveFromWindowsDirectory(value); err != nil || drive != value[:2] {
			t.Fatal("valid system directory rejected")
		}
	}
}

func TestKnownFolderObservationStrictFiniteOutput(t *testing.T) {
	good := []byte("{\"program_files\":\"valid\",\"program_data\":\"unsafe_root\",\"program_files_equal\":true,\"program_data_equal\":false}\n")
	if _, err := parseKnownFolderObservation(good); err != nil {
		t.Fatal("valid probe output rejected")
	}
	for _, raw := range [][]byte{nil, []byte("{}\n"), append(append([]byte{}, good...), good...), bytes.Replace(good, []byte("unsafe_root"), []byte(`C:\\private`), 1), bytes.Replace(good, []byte("\"program_data_equal\":false"), []byte("\"program_data_equal\":true"), 1), bytes.Replace(good, []byte("\"program_files_equal\":true"), []byte("\"program_files_equal\":false,\"program_files_equal\":true"), 1), bytes.Replace(good, []byte("}\n"), []byte(",\"extra\":false}\n"), 1)} {
		if _, err := parseKnownFolderObservation(raw); err == nil {
			t.Fatal("invalid probe output accepted")
		}
	}
}

func TestKnownFolderObservationOutputBound(t *testing.T) {
	var out knownFolderProbeOutput
	if n, err := out.Write(bytes.Repeat([]byte{'x'}, 1024)); n != 1024 || err != nil || out.overflow {
		t.Fatal("output bound rejected")
	}
	if n, err := out.Write([]byte{'x'}); n != 1 || err != nil || !out.overflow || out.Len() != 1024 {
		t.Fatal("output overflow not bounded")
	}
	out.Write(bytes.Repeat([]byte{'y'}, 4096))
	if out.Len() != 1024 {
		t.Fatal("overflow retained")
	}
}
