package windowsaction

import (
	"strings"
	"testing"
)

func TestProvisionNativeChangesStayExplicitAndDisabled(t *testing.T) {
	source := peerNativeSource(t, "provision_windows.go")
	for _, forbidden := range []string{"windows.StartService(", "windows.ControlService(", "windows.DeleteService(", "os.Remove(", "RemoveDirectory(", "SeDebugPrivilege", "SeImpersonatePrivilege", "AdjustTokenPrivileges(", "exec.Command"} {
		if strings.Contains(source, forbidden) {
			t.Fatal("provisioning added an implicit effect", forbidden)
		}
	}
	create := peerNativeFunction(t, source, "createBroker")
	if !strings.Contains(create, "windows.SERVICE_DISABLED") || !strings.Contains(create, "windows.CreateService(") || !strings.Contains(create, "sid != p.Policy.BrokerSID") {
		t.Fatal("disabled create-only broker/SID proof lost")
	}
	grant := peerNativeFunction(t, source, "grantOwnProcessQuery")
	for _, required := range []string{"uint32(os.Getpid())", "PeerProcessQueryRights", "windows.SE_KERNEL_OBJECT", "setExactDACL"} {
		if !strings.Contains(grant, required) {
			t.Fatal("exact own-process grant lost", required)
		}
	}
	for _, forbidden := range []string{"TOKEN_", "THREAD_", "PROCESS_VM_", "PROCESS_DUP_HANDLE", "DefaultDacl"} {
		if strings.Contains(grant, forbidden) {
			t.Fatal("query grant escaped process boundary", forbidden)
		}
	}
	gate := peerNativeFunction(t, source, "enableBrokerPeerQueries")
	if !strings.Contains(gate, "policy.ProvisioningVersion == \"\"") || !strings.Contains(gate, "readProvisionReceipt(policy)") || strings.Contains(gate, "fs.ErrNotExist") {
		t.Fatal("new policy falls back after lost receipt")
	}
	observer := peerNativeFunction(t, source, "EnableObserverPeerQueries")
	for _, required := range []string{"ValidateRuntimeIdentity()", "OpenObservationPeer(ctx, uint32(os.Getpid()))", "brokerPublicConfiguration(h, exe)", "brokerServiceACL(h, b, a)", "grantOwnProcessQuery(b)"} {
		if !strings.Contains(observer, required) {
			t.Fatal("observer bootstrap proof lost", required)
		}
	}
}
