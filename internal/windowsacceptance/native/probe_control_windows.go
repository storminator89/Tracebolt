//go:build windows

package native

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func acceptanceStoreOptions(create bool) windowsstate.Options {
	return windowsstate.Options{InstallerOnly: true, Names: []string{"probe-intent.json", "probe-receipt.json"}, LockName: "acceptance.lock", TempName: "acceptance.tmp", MaxBytes: 64 << 10, Create: create}
}
func (s *nativeState) acceptancePath() string {
	return filepath.Join(filepath.Dir(s.layout.StateRoot), "windows-acceptance")
}
func openProbe(rights uint32) (windows.Handle, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	return windows.OpenService(scm, windows.StringToUTF16Ptr(probeServiceName), rights)
}
func probeAbsent() bool {
	h, err := openProbe(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	if err == nil {
		windows.CloseServiceHandle(h)
		return false
	}
	return errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST)
}

type probeReceipt struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installation_id"`
	ImageSHA256    string `json:"image_sha256"`
	ServiceSID     string `json:"service_sid"`
	Complete       bool   `json:"complete"`
}

func (d *Driver) probeRecord(complete bool) probeReceipt {
	s, _ := d.native()
	return probeReceipt{1, d.receipt.InstallationID, d.options.ControllerSHA256, s.probeSID, complete}
}

func (d *Driver) probe(ctx context.Context, g Guard) error {
	s, ok := d.native()
	if !ok || !d.verifyReceipt() || !d.requireStopped(ctx) || !d.protectedObjectsExist() || s.probeCreated || !probeAbsent() {
		return d.fail(ReasonState)
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	journal, err := windowsstate.Open(s.acceptancePath(), acceptanceStoreOptions(true))
	if err != nil {
		return d.fail(ReasonState)
	}
	defer journal.Close()
	if s.captureRoot(s.acceptancePath()) != nil {
		return d.fail(ReasonOwnership)
	}
	intent, err := json.Marshal(d.probeRecord(false))
	if err != nil || !approved(ctx, g) || journal.Write("probe-intent.json", intent) != nil {
		return d.fail(ReasonState)
	}
	s.probeDescription = "Tracebolt native acceptance probe; installation=" + d.receipt.InstallationID + "; executable-sha256=" + d.options.ControllerSHA256
	image := filepath.Join(filepath.Dir(s.layout.Executable), probeExecutableName)
	// The just-provisioned controller must retain its exact ID/hash before any
	// SCM process starts; this check never rewrites changed bytes or permissions.
	if !d.objectMatches(image) || !approved(ctx, g) {
		return d.fail(ReasonOwnership)
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return d.fail(ReasonOperation)
	}
	rights := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_START | windows.SERVICE_STOP)
	h, err := windows.CreateService(scm, windows.StringToUTF16Ptr(probeServiceName), windows.StringToUTF16Ptr("Tracebolt native acceptance denial probe"), rights, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_DISABLED, windows.SERVICE_ERROR_NORMAL, windows.StringToUTF16Ptr(`"`+image+`" "`+probeArgument+`"`), nil, nil, nil, windows.StringToUTF16Ptr(windowsservice.Account), nil)
	windows.CloseServiceHandle(scm)
	if err != nil {
		return d.fail(ReasonOperation)
	}
	defer windows.CloseServiceHandle(h)
	s.probeCreated = true
	// Receipt stays incomplete until every fixed restriction has been checked.
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	desc := windows.SERVICE_DESCRIPTION{Description: windows.StringToUTF16Ptr(s.probeDescription)}
	if windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&desc))) != nil {
		return d.fail(ReasonOperation)
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	sidType := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED)
	if windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType))) != nil {
		return d.fail(ReasonOperation)
	}
	privileges := append(windows.StringToUTF16(windowsservice.RequiredPrivilege), 0)
	required := struct{ Privileges *uint16 }{&privileges[0]}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	err = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&required)))
	runtime.KeepAlive(privileges)
	if err != nil {
		return d.fail(ReasonOperation)
	}
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	if windows.ChangeServiceConfig(h, windows.SERVICE_NO_CHANGE, windows.SERVICE_DEMAND_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil) != nil {
		return d.fail(ReasonOperation)
	}
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+probeServiceName)
	if err != nil || sid == nil || !nativeServiceSID(sid.String()) || sid.String() == d.receipt.ServiceSID {
		return d.fail(ReasonOwnership)
	}
	s.probeSID = sid.String()
	if !d.probeOwned(h) {
		return d.fail(ReasonOwnership)
	}
	record, err := json.Marshal(d.probeRecord(true))
	if err != nil || !approved(ctx, g) || journal.Write("probe-receipt.json", record) != nil || journal.Close() != nil {
		return d.fail(ReasonState)
	}
	s.probeComplete = true
	if !approved(ctx, g) {
		return d.fail(ReasonGuard)
	}
	if windows.StartService(h, 0, nil) != nil {
		return d.fail(ReasonOperation)
	}
	c, cancel := context.WithTimeout(ctx, operationBound)
	defer cancel()
	for {
		if !d.probeOwned(h) {
			return d.fail(ReasonOwnership)
		}
		status, valid := queryProbeStatus(h)
		if !valid {
			return d.fail(ReasonOperation)
		}
		if status.CurrentState == windows.SERVICE_STOPPED {
			if status.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) || status.ServiceSpecificExitCode != ProbeDeniedExitCode {
				return d.fail(ReasonOperation)
			}
			d.evidence.UnrelatedServiceDenied = true
			return nil
		}
		if wait(c) != nil {
			return d.fail(ReasonTimeout)
		}
	}
}
func queryProbeStatus(h windows.Handle) (windows.SERVICE_STATUS_PROCESS, bool) {
	var s windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&s)), uint32(unsafe.Sizeof(s)), &needed)
	return s, err == nil && s.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS
}
func (d *Driver) probeOwned(h windows.Handle) bool {
	s, ok := d.native()
	if !ok || !s.probeCreated || s.probeSID == "" {
		return false
	}
	c, err := (&mgr.Service{Name: probeServiceName, Handle: h}).Config()
	if err != nil || c.Description != s.probeDescription || !probeFixedConfiguration(c, filepath.Join(filepath.Dir(s.layout.Executable), probeExecutableName)) {
		return false
	}
	p, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if !ok || !probeOnlyChangeNotify(p) {
		return false
	}
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+probeServiceName)
	if err != nil || sid == nil || sid.String() != s.probeSID {
		return false
	}
	// Conservatively refuse unexpected failure actions/triggers, including a
	// nonzero failure-action flag, before any lifecycle or cleanup operation.
	for _, kind := range []uint32{windows.SERVICE_CONFIG_TRIGGER_INFO, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG} {
		b, ok := probeQueryConfig2(h, kind)
		if !ok || len(b) < 4 || *(*uint32)(unsafe.Pointer(&b[0])) != 0 {
			return false
		}
	}
	b, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS)
	if !ok || len(b) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
		return false
	}
	a := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&b[0]))
	valid := a.ActionsCount == 0 && probeEmptyUTF16(b, a.RebootMsg) && probeEmptyUTF16(b, a.Command)
	runtime.KeepAlive(b)
	return valid
}
func (d *Driver) verifyProbeReceipt() bool {
	s, ok := d.native()
	if !ok || !s.probeCreated || !s.probeComplete {
		return false
	}
	st, err := windowsstate.Open(s.acceptancePath(), acceptanceStoreOptions(false))
	if err != nil {
		return false
	}
	defer st.Close()
	raw, err := st.Read("probe-receipt.json")
	if err != nil {
		return false
	}
	defer clear(raw)
	want, err := json.Marshal(d.probeRecord(true))
	return err == nil && string(raw) == string(want)
}
func (d *Driver) deleteProbe(ctx context.Context, g Guard) error {
	s, _ := d.native()
	if !s.probeCreated {
		return nil
	}
	if !d.verifyProbeReceipt() {
		return d.fail(ReasonOwnership)
	}
	h, err := openProbe(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.SERVICE_STOP | windows.DELETE)
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	if !d.probeOwned(h) {
		windows.CloseServiceHandle(h)
		return d.fail(ReasonOwnership)
	}
	c, cancel := context.WithTimeout(ctx, operationBound)
	defer cancel()
	for {
		status, ok := queryProbeStatus(h)
		if !ok {
			windows.CloseServiceHandle(h)
			return d.fail(ReasonOperation)
		}
		if status.CurrentState == windows.SERVICE_STOPPED {
			break
		}
		if status.CurrentState == windows.SERVICE_RUNNING {
			if !approved(c, g) || !d.probeOwned(h) {
				windows.CloseServiceHandle(h)
				return d.fail(ReasonGuard)
			}
			var status windows.SERVICE_STATUS
			if windows.ControlService(h, windows.SERVICE_CONTROL_STOP, &status) != nil {
				windows.CloseServiceHandle(h)
				return d.fail(ReasonOperation)
			}
		}
		if wait(c) != nil {
			windows.CloseServiceHandle(h)
			return d.fail(ReasonTimeout)
		}
	}
	if !approved(c, g) || !d.probeOwned(h) {
		windows.CloseServiceHandle(h)
		return d.fail(ReasonOwnership)
	}
	err = windows.DeleteService(h)
	windows.CloseServiceHandle(h)
	if err != nil {
		return d.fail(ReasonOperation)
	}
	for {
		if probeAbsent() {
			s.probeDeleted = true
			return nil
		}
		if wait(c) != nil {
			return d.fail(ReasonTimeout)
		}
	}
}
