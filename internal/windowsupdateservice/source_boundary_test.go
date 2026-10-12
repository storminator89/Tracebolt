package windowsupdateservice

import (
	"context"
	"localrmm/internal/windowsupdateipc"
	"os"
	"strings"
	"testing"
)

func TestBackgroundServiceSourceBoundaries(t *testing.T) {
	for name, required := range map[string][]string{"runtime_windows.go": {"svc.IsWindowsService", "ProductType == 2", "VerifyServiceContext", "OpenWindowsUpdatePublicAuthority", "StopPending", "CheckPoint: checkpoint", "adapter.StopAdmission()", "adapter.Drain(context.Background())", "OpenCoordinatedExecutor"}, "scm_windows.go": {"SERVICE_WIN32_OWN_PROCESS", "StartDisabled", "LocalSystem", "0x20005", "len(actions) != 0", "StartAutomatic"}, "../windowsupdateipc/service_peer_windows.go": {"SC_MANAGER_CONNECT", "SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS", "CheckServiceDescriptor", "ProcessId != pid", "LocalSystem"}, "../windowsupdateipc/service_guard_windows.go": {"holdExecutable", "hashHandle", "checkHeldExecutable", "processQueryRights", "checkUpdateServiceSCM"}, "../lanclient/windows_update_public_authority.go": {"validateUpdatesActivatedBytes", "renewalidentity.Parse", "senderBinding", "WindowsBackgroundUpdateRelayGrantVersion"}} {
		raw, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		for _, want := range required {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s missing %s", name, want)
			}
		}
	}
	raw, e := os.ReadFile("../lanclient/windows_update_public_authority.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"Load(path)", "ReadProtected(c.PrivateKeyFile", "tls.X509KeyPair(", "http.NewRequest"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private/network authority", forbidden)
		}
	}
}
func TestBackgroundActivationCannotAdoptOldConfig(t *testing.T) {
	if CheckProfile(context.Background(), windowsupdateipc.Config{Version: windowsupdateipc.ConfigVersion}) == nil {
		t.Fatal("old foreground config accepted")
	}
}
