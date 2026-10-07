//go:build windows

package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"localrmm/internal/windowsservice"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestProbeAcceptsOnlyActualAccessDenied(t *testing.T) {
	if !probeAccessDenied(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("actual native access denial rejected")
	}
	for _, err := range []error{nil, windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_SHARING_VIOLATION, windows.STATUS_ACCESS_DENIED, errors.New("access denied"), fmt.Errorf("policy wrapper: %w", windows.ERROR_ACCESS_DENIED), windowsservice.ErrUnsafeIdentity} {
		if probeAccessDenied(err) {
			t.Fatal("non-native denial counted")
		}
	}
}

func TestProbeReadTargetsRequiresBothAndHonorsCancellation(t *testing.T) {
	paths := []string{`C:\synthetic\agent-key.pem`, `C:\synthetic\state.json`}
	var calls []string
	if code := probeReadTargets(context.Background(), paths, func(p string) bool { calls = append(calls, p); return true }); code != ProbeDeniedExitCode || len(calls) != 2 || calls[0] != paths[0] || calls[1] != paths[1] {
		t.Fatal("both synthetic denials required")
	}
	for _, failed := range paths {
		if code := probeReadTargets(context.Background(), paths, func(p string) bool { return p != failed }); code != probeReadExitCode {
			t.Fatal("one failed denial accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = nil
	code := probeReadTargets(ctx, paths, func(p string) bool { calls = append(calls, p); cancel(); return true })
	if code != probeCanceledExitCode || len(calls) != 1 {
		t.Fatal("cancellation did not stop read attempts")
	}
	if code := probeReadTargets(ctx, paths, func(string) bool { t.Fatal("canceled context opened a target"); return false }); code != probeCanceledExitCode {
		t.Fatal("cancellation mislabeled")
	}
}

func TestProbeFixedConfiguration(t *testing.T) {
	image := `C:\Program Files\Tracebolt\tracebolt-windows-acceptance.exe`
	valid := func() mgr.Config {
		return mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: windows.SERVICE_DEMAND_START, ErrorControl: windows.SERVICE_ERROR_NORMAL, BinaryPathName: `"` + image + `" "` + probeArgument + `"`, ServiceStartName: windowsservice.Account, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}
	}
	if !probeFixedConfiguration(valid(), image) {
		t.Fatal("fixed configuration rejected")
	}
	tests := map[string]func(*mgr.Config){
		"extra argument": func(c *mgr.Config) { c.BinaryPathName += ` "--other"` },
		"shell":          func(c *mgr.Config) { c.BinaryPathName = `cmd.exe /c ` + c.BinaryPathName },
		"other account":  func(c *mgr.Config) { c.ServiceStartName = "LocalSystem" },
		"shared process": func(c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS },
		"automatic":      func(c *mgr.Config) { c.StartType = windows.SERVICE_AUTO_START },
		"restricted SID": func(c *mgr.Config) { c.SidType = windows.SERVICE_SID_TYPE_RESTRICTED },
		"no SID":         func(c *mgr.Config) { c.SidType = windows.SERVICE_SID_TYPE_NONE },
		"dependency":     func(c *mgr.Config) { c.Dependencies = []string{"other"} },
		"group":          func(c *mgr.Config) { c.LoadOrderGroup = "other" },
		"delayed start":  func(c *mgr.Config) { c.DelayedAutoStart = true },
		"tag":            func(c *mgr.Config) { c.TagId = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(&c)
			if probeFixedConfiguration(c, image) {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestProbeOwnStatus(t *testing.T) {
	s := windows.SERVICE_STATUS_PROCESS{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, CurrentState: windows.SERVICE_START_PENDING}
	if !probeOwnStatus(s, 42) {
		t.Fatal("startup PID must not be interpreted")
	}
	s.CurrentState, s.ProcessId = windows.SERVICE_RUNNING, 42
	if !probeOwnStatus(s, 42) || probeOwnStatus(s, 43) || probeOwnStatus(s, 0) {
		t.Fatal("running PID binding failed")
	}
	s.CurrentState = windows.SERVICE_STOPPED
	if probeOwnStatus(s, 42) {
		t.Fatal("stopped service accepted")
	}
}

func probePrivilegeFixture(value string) []byte {
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	b := make([]byte, ptrSize+(len(value)+2)*2)
	*(*uintptr)(unsafe.Pointer(&b[0])) = uintptr(unsafe.Pointer(&b[ptrSize]))
	for i := range value {
		binary.LittleEndian.PutUint16(b[ptrSize+i*2:], uint16(value[i]))
	}
	return b
}

func TestProbeExactRequiredPrivileges(t *testing.T) {
	if !probeOnlyChangeNotify(probePrivilegeFixture("SeChangeNotifyPrivilege")) {
		t.Fatal("exact required privilege rejected")
	}
	for _, value := range []string{"", "SeDebugPrivilege", "SeChangeNotifyPrivilege\x00SeDebugPrivilege", "SeChangeNotifyPrivilegeSuffix"} {
		if probeOnlyChangeNotify(probePrivilegeFixture(value)) {
			t.Fatal("unexpected privilege list accepted")
		}
	}
	b := probePrivilegeFixture("SeChangeNotifyPrivilege")
	if probeOnlyChangeNotify(b[:len(b)-2]) {
		t.Fatal("missing multistring terminator accepted")
	}
	*(*uintptr)(unsafe.Pointer(&b[0])) = 0
	if probeOnlyChangeNotify(b) {
		t.Fatal("null privilege list accepted")
	}
}

func TestProbeDescriptionExactBinding(t *testing.T) {
	id, digest := strings.Repeat("01", 16), strings.Repeat("ab", 32)
	description := "Tracebolt native acceptance probe; installation=" + id + "; executable-sha256=" + digest
	gotID, gotDigest, ok := probeDescriptionBinding(description)
	if !ok || gotID != id || gotDigest != digest {
		t.Fatal("exact source/installation binding rejected")
	}
	for _, changed := range []string{"", strings.ToUpper(description), description + "; other=value", strings.Replace(description, id, "other", 1), strings.Replace(description, digest, strings.Repeat("zz", 32), 1), strings.Replace(description, "probe;", "service;", 1)} {
		if _, _, ok := probeDescriptionBinding(changed); ok {
			t.Fatal("malformed source binding accepted")
		}
	}
}

func TestProbeHandlerEarlyRejectionsDoNotReachNativeChecks(t *testing.T) {
	for _, args := range [][]string{nil, {probeServiceName, "extra"}, {"OtherService"}} {
		h := &denialProbeHandler{ctx: context.Background(), result: make(chan uint32, 1)}
		changes := make(chan svc.Status, 1)
		specific, code := h.Execute(args, nil, changes)
		if !specific || code != probeContextExitCode || <-h.result != code || len(changes) != 0 {
			t.Fatal("bad dispatcher arguments were accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &denialProbeHandler{ctx: ctx, result: make(chan uint32, 1)}
	changes := make(chan svc.Status, 1)
	specific, code := h.Execute([]string{probeServiceName}, nil, changes)
	if !specific || code != probeCanceledExitCode || <-h.result != code || (<-changes).State != svc.StartPending {
		t.Fatal("canceled handler reached native validation")
	}
}
