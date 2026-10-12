package windowsmanagedmsiipc

import (
	job "localrmm/internal/windowsmanagedmsi"
	"os"
	"strings"
	"testing"
)

func TestManagedPipeFreshDomainAndBoundedPayload(t *testing.T) {
	if PipeName != `\\.\pipe\Tracebolt.Windows.ManagedMSI.v1` || MaxMessageBytes != job.MaxFrameBytes || job.MaxChunkBytes != 32<<10 {
		t.Fatal("domain/budget changed")
	}
	for _, op := range []string{"shell", "url", "path", "install-prepared", "download"} {
		if (request{Version: Version, Operation: op}).validate() == nil {
			t.Fatal(op)
		}
	}
}
func TestManagedRuntimeNativeSourceBoundaries(t *testing.T) {
	for file, required := range map[string][]string{"ipc_windows.go": {"windows.SC_MANAGER_CONNECT", "windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS", "CheckServiceDescriptor", "SECURITY_IDENTIFICATION", "PIPE_REJECT_REMOTE_CLIENTS"}, "observer_windows.go": {"OpenObservationPeer", "observerPipeIdentity", "RevertToSelf"}, "../windowsmanagedmsiservice/runtime_windows.go": {"VerifyServiceToken", "ProductType == 2", "OpenWindowsManagedMSIPublicAuthority", "x.Wait()"}, "../windowsmanagedmsiexecutor/native_windows.go": {"MsiInstallProductW", "REBOOT=ReallySuppress", "CheckNativeInstallStart"}} {
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		for _, want := range required {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s missing %s", file, want)
			}
		}
	}
	raw, e := os.ReadFile("../lanclient/windows_managed_msi_authority.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(raw)
	if strings.Contains(s, "tls.X509KeyPair(") || strings.Contains(s, "Load(path)") || strings.Contains(s, "ReadProtected(c.PrivateKeyFile") || strings.Contains(s, "http.NewRequest") {
		t.Fatal("deployment runtime touched enrollment key/network client")
	}
}
