package windowsusersoftwarelocal

import (
	"os"
	"strings"
	"testing"
)

// Static fixtures are source checks only; they are not Windows acceptance.
func TestFixedReadOnlySourceAndIPCSeparation(t *testing.T) {
	sources := map[string][]string{
		"registry_windows.go": {"registry.CURRENT_USER", "reg", "DisplayName", "DisplayVersion", "Publisher"},
		"msix_windows.go":     {"manager.call(12,0,", "id.text(12)", "id.text(6)", "id.text(10)", "deferdeleteHString.Call(h)", "returncopyHString(ptr,n,", "windows.ReadProcessMemory(windows.CurrentProcess(),address,"},
		"ipc_windows.go":      {"FILE_FLAG_FIRST_PIPE_INSTANCE", "PIPE_REJECT_REMOTE_CLIENTS", "InheritHandle:0", "SECURITY_IDENTIFICATION"},
		"peer_windows.go":     {"OpenCurrentProcessToken", "SecurityIdentification", "OpenThreadToken", "RevertToSelf", "TOKEN_QUERY", "SERVICE_WIN32_OWN_PROCESS", "serviceRunning", "TokenElevation", "TokenIntegrityLevel", "TokenSessionId"},
	}
	for file, markers := range sources {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		s := string(b)
		if file == "msix_windows.go" && !comForwarderLifetimeSource(s) {
			t.Fatal("COM forwarding must preserve caller pointer lifetime with uintptrescapes; pointer conversions stay directly in call arguments")
		}
		compact := strings.NewReplacer(" ", "", "\t", "", "\n", "").Replace(s)
		for _, marker := range markers {
			if !strings.Contains(compact, strings.ReplaceAll(marker, " ", "")) {
				t.Fatalf("%s misses %s", file, marker)
			}
		}
		for _, forbidden := range []string{`"os/exec"`, `"localrmm/internal/windowsaction"`, `registry.LOCAL_MACHINE`, `registry.USERS`, `registry.WOW64_32KEY`, `registry.WOW64_64KEY`, `windows.OpenProcessToken(`, `windows.OpenProcess(`, `unsafe.Pointer(ptr)`, `AdjustTokenPrivileges(`, `SetSecurityInfo(`} {
			if strings.Contains(s, forbidden) {
				t.Fatalf("%s crosses source boundary: %s", file, forbidden)
			}
		}
	}
}

func TestIdentityOnlyPipeQueryAndPublicServerProof(t *testing.T) {
	b, e := os.ReadFile("peer_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, required := range []string{"OpenCurrentProcessToken", "OpenThreadToken", "RevertToSelf", "runtime.LockOSThread", "if clean", "SecurityIdentification", "GetNamedPipeClientSessionId", "!identification", "stats[8:16]"} {
		if !strings.Contains(s, required) {
			t.Fatalf("missing identity boundary %s", required)
		}
	}
	for _, bad := range []string{"OpenProcessToken(", "WTSQuerySessionInformation", "activeSession(", "TOKEN_DUPLICATE", "TOKEN_IMPERSONATE", "SeDebugPrivilege", "SeImpersonatePrivilege"} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden foreign privilege dependency %s", bad)
		}
	}
	b, e = os.ReadFile("../windowsservice/observation_peer_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(b)
	for _, required := range []string{"PROCESS_QUERY_LIMITED_INFORMATION", "SERVICE_QUERY_CONFIG", "observationServiceDescriptor", "observationPublicConfiguration", "QueryFullProcessImageName"} {
		if !strings.Contains(s, required) {
			t.Fatalf("missing public proof %s", required)
		}
	}
	for _, bad := range []string{"OpenProcessToken(", "InspectOwned(", "LoadReceipt(", "ApplyInstall(", "ApplyStart(", "verifyExecutable(", "os.Open(", "ReadFile(", "SERVICE_CHANGE_CONFIG", "READ_CONTROL|windows.SYNCHRONIZE"} {
		if strings.Contains(s, bad) {
			t.Fatalf("proof exceeds read-only public scope %s", bad)
		}
	}
}

// Windows checkouts may use CRLF. Normalize only line endings; the directive
// must still be immediately adjacent to this exact forwarding declaration.
func comForwarderLifetimeSource(source string) bool {
	return strings.Contains(strings.ReplaceAll(source, "\r\n", "\n"), "//go:uintptrescapes\nfunc (p *comObject) call(index int, args ...uintptr) error {")
}

func TestCOMForwarderLifetimeSourceLineEndings(t *testing.T) {
	declaration := "func (p *comObject) call(index int, args ...uintptr) error {"
	for _, ending := range []string{"\n", "\r\n"} {
		valid := "//go:uintptrescapes" + ending + declaration
		if !comForwarderLifetimeSource(valid) {
			t.Fatalf("valid line ending %q rejected", ending)
		}
		for _, invalid := range []string{declaration, "//go:noinline" + ending + declaration, "//go:uintptrescapes" + ending + "func other() {}" + ending + declaration, "//go:uintptrescapes" + ending + strings.Replace(declaration, "call(", "other(", 1)} {
			if comForwarderLifetimeSource(invalid) {
				t.Fatalf("missing or misplaced lifetime contract accepted for %q", ending)
			}
		}
	}
}
