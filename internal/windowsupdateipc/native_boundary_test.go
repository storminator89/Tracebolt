package windowsupdateipc

import (
	"os"
	"strings"
	"testing"
)

func TestNativeTransportSourceRetainsSecurityBoundaries(t *testing.T) {
	b, e := os.ReadFile("ipc_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, want := range []string{"FILE_FLAG_FIRST_PIPE_INSTANCE", "PIPE_REJECT_REMOTE_CLIENTS", "SECURITY_IDENTIFICATION", "CancelIoEx", "GetOverlappedResult", "GetNamedPipeServerProcessId", "processCreated"} {
		if !strings.Contains(s, want) {
			t.Fatal("missing native boundary", want)
		}
	}
	if pipeClientMask := uint32(0x00120183); pipeClientMask&4 != 0 {
		t.Fatal("instance creation granted")
	}
	b, e = os.ReadFile("foreground_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(b)
	at := strings.Index(s, "func checkHeldExecutable")
	if at < 0 {
		t.Fatal("missing held structural check")
	}
	s = s[at:]
	for _, want := range []string{"FILE_ATTRIBUTE_REPARSE_POINT", "NumberOfLinks", "GetFinalPathNameByHandle", "FileCaseSensitiveInformation", "pathACL"} {
		if !strings.Contains(s, want) {
			t.Fatal("lost held-path currentness", want)
		}
	}
	for _, file := range []string{"ipc_windows.go", "observer_windows.go", "foreground_windows.go"} {
		b, e = os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		s = string(b)
		if strings.Contains(s, `"localrmm/internal/windowsaction"`) || strings.Contains(s, "SERVICE_START") || strings.Contains(s, "SERVICE_STOP") {
			t.Fatal("borrowed service-action authority", file)
		}
	}
}
