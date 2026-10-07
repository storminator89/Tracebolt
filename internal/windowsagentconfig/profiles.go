// Package windowsagentconfig fixes the separate Windows basic TLS store schemas.
// It does not inspect, create, install, grant access or contact any host itself.
package windowsagentconfig

import "localrmm/internal/windowsstate"

func Enrollment(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json", "service-enrollment.json"}, Directories: []string{"telemetry"}, LockName: "enrollment.lock", TempName: "enrollment.tmp", MaxBytes: 1 << 20, Create: create}
}
func Sender(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"state.json"}, LockName: "sender.lock", TempName: "sender.tmp", MaxBytes: 128 << 10, Create: create}
}
func RuntimeRoot(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"bootstrap.json"}, Directories: []string{"enrollment"}, LockName: "runtime.lock", TempName: "runtime.tmp", MaxBytes: 64 << 10, Create: create}
}
func Installer(create bool) windowsstate.Options {
	return windowsstate.Options{InstallerOnly: true, Names: []string{"intent.json", "receipt.json"}, LockName: "installer.lock", TempName: "installer.tmp", MaxBytes: 64 << 10, Create: create}
}
