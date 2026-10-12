package windowsaction

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// These are source-only boundary fixtures, not native Windows acceptance.
func peerNativeSource(t *testing.T, name string) string {
	t.Helper()
	b, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func peerNativeFunction(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, e := parser.ParseFile(fset, "source.go", source, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return source[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
		}
	}
	t.Fatal("missing function", name)
	return ""
}
func TestActionPeerPrimaryTokenIsSelfOnly(t *testing.T) {
	source := peerNativeSource(t, "peer_windows.go")
	if strings.Count(source, "windows.OpenProcessToken(") != 1 || !strings.Contains(peerNativeFunction(t, source, "openOwnBrokerPeer"), "windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.READ_CONTROL, &token)") {
		t.Fatal("primary token access is not confined to the current process")
	}
	own := peerNativeFunction(t, source, "openOwnBrokerPeer")
	for _, required := range []string{"validateBrokerKernelObjects(process, token, pid, sid, logon)", "brokerLogonSID", "token.IsRestricted()", "TokenRestrictedSids", "brokerServiceACL", "SERVICE_SID_TYPE_RESTRICTED", "SeChangeNotifyPrivilege", "QueryFullProcessImageName"} {
		if !strings.Contains(own, required) {
			t.Fatal("self guard removed", required)
		}
	}
	for _, forbidden := range []string{"TOKEN_DUPLICATE", "TOKEN_IMPERSONATE", "AdjustTokenPrivileges(", "SeDebugPrivilege", "SeImpersonatePrivilege", "SetSecurityInfo(", "SetNamedSecurityInfo("} {
		if strings.Contains(source, forbidden) {
			t.Fatal("peer proof widens authority", forbidden)
		}
	}
}
func TestActionPublicBrokerProofNeedsNoForeignTokenOrPrivateFile(t *testing.T) {
	source := peerNativeSource(t, "peer_windows.go")
	public := peerNativeFunction(t, source, "openBrokerPeer") + peerNativeFunction(t, source, "brokerPublicConfiguration")
	for _, required := range []string{"PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE", "SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL", "BrokerName", "BrokerAccount", "SERVICE_SID_TYPE_RESTRICTED", "validBrokerPublicMarker"} {
		if !strings.Contains(public, required) {
			t.Fatal("missing public broker proof", required)
		}
	}
	for _, forbidden := range []string{"OpenProcessToken", "OpenThreadToken", "holdExecutable", "hashHandle", "os.Open", "ReadFile(", "AuthorityPath", "InspectOwned", "LoadReceipt", "SERVICE_CHANGE_CONFIG", "PROCESS_DUP_HANDLE"} {
		if strings.Contains(public, forbidden) {
			t.Fatal("public proof crossed boundary", forbidden)
		}
	}
	if !strings.Contains(source, "!livePeerProcess(p.process)") || !strings.Contains(peerNativeFunction(t, source, "livePeerProcess"), "windows.WaitForSingleObject(process, 0)") || !strings.Contains(peerNativeFunction(t, source, "livePeerProcess"), "windows.WAIT_TIMEOUT") {
		t.Fatal("held process liveness lost, including exit code 259")
	}
	observer := peerNativeFunction(t, source, "openObservationPeer")
	if !strings.Contains(observer, "windowsservice.OpenObservationPeer(ctx, pid)") || !strings.Contains(observer, "PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE") || !strings.Contains(observer, "observerPipeIdentity(pipe, sid)") {
		t.Fatal("observer identity not bound to protected public SCM and held live process")
	}
}
func TestActionPipeIdentityRevertsBeforeAnyAdmission(t *testing.T) {
	source := peerNativeSource(t, "peer_windows.go")
	query := peerNativeFunction(t, source, "actionPipeIdentificationToken")
	for _, required := range []string{"runtime.LockOSThread()", "if clean", "runtime.UnlockOSThread()", "!noActionThreadImpersonation()", "windows.TOKEN_QUERY, true, &token", "windows.RevertToSelf()", "windows.TokenImpersonation", "windows.SecurityIdentification", "errPeerRevert"} {
		if !strings.Contains(query, required) {
			t.Fatal("missing identity isolation", required)
		}
	}
	open := strings.Index(query, "openErr := windows.OpenThreadToken")
	revert := strings.Index(query, "revertErr := windows.RevertToSelf()")
	typeCheck := strings.Index(query, "typ, e := peerTokenNumber")
	if open < 0 || revert <= open || typeCheck <= revert || !strings.Contains(query[revert:typeCheck], "!noActionThreadImpersonation()") {
		t.Fatal("identity token escaped before verified revert")
	}
	for _, forbidden := range []string{"dispatch(", "StartService(", "ControlService(", "OpenService(", "ReadFile(", "WriteFile(", "TOKEN_DUPLICATE", "TOKEN_IMPERSONATE"} {
		if strings.Contains(query, forbidden) {
			t.Fatal("effect-capable identity use", forbidden)
		}
	}
	server := peerNativeFunction(t, peerNativeSource(t, "ipc_windows.go"), "serveReady")
	read := strings.Index(server, "raw, e := readFrame(reqCtx, h)")
	admit := strings.Index(server, "openObservationPeer(reqCtx, h, b.policy.AgentSID)")
	dispatch := strings.Index(server, "response := dispatch(reqCtx, b, raw)")
	if read < 0 || admit <= read || dispatch <= admit {
		t.Fatal("first bounded read must precede identity acquisition and dispatch")
	}
	for _, required := range []string{"50*time.Second", "peer.failedRevert", "errors.Is(conversationErr, errPeerRevert)", "return errPeerRevert"} {
		if !strings.Contains(server, required) {
			t.Fatal("missing request/revert fail-closed boundary", required)
		}
	}
	client := peerNativeFunction(t, peerNativeSource(t, "ipc_windows.go"), "callNative")
	if !strings.Contains(client, "windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION") || strings.Index(client, "openBrokerPeer(h, pid, sid)") > strings.Index(client, "writeFrame(ctx, h, raw)") {
		t.Fatal("client must request identification only and prove broker before writing")
	}
}
