//go:build windows

package windowsservice

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

// ValidateObservationWorker verifies the inherited restricted service identity,
// fixed protected executable, and actual live creator's SCM identity. It neither
// reads the administrator-only installer receipt nor changes ACLs or state.
func ValidateObservationWorker(ctx context.Context) (ObservationWorkerIdentity, error) {
	if ctx == nil {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	if err := ctx.Err(); err != nil {
		return ObservationWorkerIdentity{}, err
	}
	if err := ValidateRuntimeIdentity(); err != nil {
		return ObservationWorkerIdentity{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	var info windows.PROCESS_BASIC_INFORMATION
	size := uint32(unsafe.Sizeof(info))
	returned := uint32(0)
	if windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessBasicInformation, unsafe.Pointer(&info), size, &returned) != nil || returned != size || info.UniqueProcessId != uintptr(os.Getpid()) || info.InheritedFromUniqueProcessId == 0 || info.InheritedFromUniqueProcessId > 1<<32-1 {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(info.InheritedFromUniqueProcessId))
	if err != nil {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	defer windows.CloseHandle(parent)
	var pc, wc, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(parent, &pc, &exit, &kernel, &user) != nil || windows.GetProcessTimes(windows.CurrentProcess(), &wc, &exit, &kernel, &user) != nil {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	result, err := windows.WaitForSingleObject(parent, 0)
	if err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	process := observationWorkerProcess{uint32(info.UniqueProcessId), uint32(info.InheritedFromUniqueProcessId), uint64(wc.HighDateTime)<<32 | uint64(wc.LowDateTime), uint64(pc.HighDateTime)<<32 | uint64(pc.LowDateTime), true}
	binding, err := validateObservationWorker(ctx, ValidateRuntimeIdentity, nativeBackend(), executable, process)
	if err != nil {
		return ObservationWorkerIdentity{}, err
	}
	result, err = windows.WaitForSingleObject(parent, 0)
	if err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		return ObservationWorkerIdentity{}, ErrMismatch
	}
	return binding, nil
}
