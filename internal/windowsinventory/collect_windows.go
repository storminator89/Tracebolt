//go:build windows

package windowsinventory

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"localrmm/internal/collector"
	"localrmm/internal/model"
)

type nativeProvider struct{}

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var getSystemTimes = kernel.NewProc("GetSystemTimes")
var getActiveProcessorGroupCount = kernel.NewProc("GetActiveProcessorGroupCount")
var errInvalid = errors.New("native reading is unavailable")

// Collect performs only fixed local read APIs. This function never requests
// elevation, changes token privileges, creates services or runs a shell.
func Collect(ctx context.Context) (Report, error) {
	return collect(ctx, nativeProvider{}, func(ctx context.Context) error {
		timer := time.NewTimer(cpuInterval)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
}
func (nativeProvider) system() model.Device { return collector.Snapshot() }
func (nativeProvider) cpu() (cpuTimes, error) {
	if err := getActiveProcessorGroupCount.Find(); err != nil {
		return cpuTimes{}, err
	}
	groups, _, _ := getActiveProcessorGroupCount.Call()
	// Refuse group-limited data rather than present it as whole-system CPU.
	if groups != 1 {
		return cpuTimes{}, errInvalid
	}
	if err := getSystemTimes.Find(); err != nil {
		return cpuTimes{}, err
	}
	var idle, kernel, user windows.Filetime
	ok, _, err := getSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = errInvalid
		}
		return cpuTimes{}, err
	}
	ticks := func(v windows.Filetime) uint64 { return uint64(v.HighDateTime)<<32 | uint64(v.LowDateTime) }
	return cpuTimes{ticks(idle), ticks(kernel), ticks(user)}, nil
}
func (nativeProvider) hostname() result[Hostname] {
	value, err := os.Hostname()
	r := result[Hostname]{complete: err == nil, err: err}
	if err == nil {
		r.rows = []Hostname{{Value: value}}
	}
	return r
}
func (nativeProvider) processes(ctx context.Context) result[Process] {
	r := result[Process]{}
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		r.err = err
		return r
	}
	defer windows.CloseHandle(h)
	var p windows.ProcessEntry32
	p.Size = uint32(unsafe.Sizeof(p))
	err = windows.Process32First(h, &p)
	for err == nil {
		if ctx.Err() != nil {
			r.err = ctx.Err()
			return r
		}
		if len(r.rows) >= MaxProcesses {
			r.truncated = true
			return r
		}
		r.rows = append(r.rows, Process{PID: p.ProcessID, ParentPID: p.ParentProcessID, Name: windows.UTF16ToString(p.ExeFile[:]), Threads: p.Threads})
		p.Size = uint32(unsafe.Sizeof(p))
		err = windows.Process32Next(h, &p)
	}
	r.complete = errors.Is(err, windows.ERROR_NO_MORE_FILES)
	if !r.complete {
		r.err = err
	}
	return r
}
func (nativeProvider) services(ctx context.Context) result[Service] {
	r := result[Service]{}
	if ctx.Err() != nil {
		r.err = ctx.Err()
		return r
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		r.err = err
		return r
	}
	defer windows.CloseServiceHandle(manager)
	// Windows documents 256 KiB as the maximum enumeration buffer. One bounded
	// read may return fewer services than exist; preserve that truncation.
	buf := make([]byte, 256<<10)
	var needed, count, resume uint32
	err = windows.EnumServicesStatusEx(manager, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		r.err = err
		return r
	}
	size := unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})
	if uint64(count) > uint64(len(buf))/uint64(size) {
		r.err = errInvalid
		return r
	}
	r.complete = err == nil
	r.truncated = errors.Is(err, windows.ERROR_MORE_DATA)
	for i := uint32(0); i < count; i++ {
		if ctx.Err() != nil {
			r.err = ctx.Err()
			r.complete = false
			return r
		}
		if len(r.rows) >= MaxServices {
			r.truncated = true
			r.complete = false
			break
		}
		entry := (*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[uintptr(i)*size]))
		name, nok := bufferString(buf, entry.ServiceName)
		display, dok := bufferString(buf, entry.DisplayName)
		if !nok || !dok {
			r.complete = false
			continue
		}
		r.rows = append(r.rows, Service{Name: name, DisplayName: display, State: serviceState(entry.ServiceStatusProcess.CurrentState), PID: entry.ServiceStatusProcess.ProcessId})
	}
	runtime.KeepAlive(buf)
	return r
}

// Returned pointers are accepted only inside the original buffer, aligned and
// terminated within a bounded string. No unbounded UTF16PtrToString reads.
func bufferString(buf []byte, p *uint16) (string, bool) {
	if len(buf) == 0 || p == nil {
		return "", false
	}
	start, addr := uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(p))
	if addr < start || addr-start >= uintptr(len(buf)) || (addr-start)%2 != 0 {
		return "", false
	}
	remaining := (uintptr(len(buf)) - (addr - start)) / 2
	if remaining > 257 {
		remaining = 257
	}
	values := unsafe.Slice(p, int(remaining))
	for i, v := range values {
		if v == 0 {
			return windows.UTF16ToString(values[:i]), true
		}
	}
	return "", false
}
func serviceState(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return "unknown"
}

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func (nativeProvider) software(ctx context.Context) result[Software] {
	r := result[Software]{complete: true}
	// Pin the thread across each registry enumeration; Go issue 49320.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, view := range []struct {
		name string
		flag uint32
	}{{"64", registry.WOW64_64KEY}, {"32", registry.WOW64_32KEY}} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPath, registry.ENUMERATE_SUB_KEYS|view.flag)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			r.complete = false
			r.err = err
			continue
		}
		for index := uint32(0); ; index++ {
			if ctx.Err() != nil {
				key.Close()
				r.err = ctx.Err()
				r.complete = false
				return r
			}
			// Bound work by keys visited, including unnamed/invalid registrations.
			if index >= MaxSoftware {
				r.complete = false
				r.truncated = true
				break
			}
			var name [256]uint16
			length := uint32(len(name))
			err := windows.RegEnumKeyEx(windows.Handle(key), index, &name[0], &length, nil, nil, nil, nil)
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			if err != nil {
				r.complete = false
				r.err = err
				break
			}
			sub, err := registry.OpenKey(key, windows.UTF16ToString(name[:length]), registry.QUERY_VALUE|view.flag)
			if err != nil {
				r.complete = false
				r.err = err
				continue
			}
			display, displayErr := registryString(sub, "DisplayName")
			version, versionErr := registryString(sub, "DisplayVersion")
			publisher, publisherErr := registryString(sub, "Publisher")
			sub.Close()
			if displayErr != nil || versionErr != nil || publisherErr != nil {
				r.complete = false
				continue
			}
			if display == "" {
				continue
			}
			if len(r.rows) >= MaxSoftware {
				r.complete = false
				r.truncated = true
				break
			}
			r.rows = append(r.rows, Software{Name: display, Version: version, Publisher: publisher, RegistryView: view.name})
		}
		key.Close()
	}
	return r
}
func registryString(key registry.Key, name string) (string, error) {
	p, _ := windows.UTF16PtrFromString(name)
	var typ uint32
	var buf [514]byte
	size := uint32(len(buf))
	err := windows.RegQueryValueEx(windows.Handle(key), p, nil, &typ, &buf[0], &size)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	// Do not expand environment strings or read arbitrary-length values.
	if typ != windows.REG_SZ || size < 2 || size > uint32(len(buf)) || size%2 != 0 {
		return "", errInvalid
	}
	values := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), int(size)/2)
	if values[len(values)-1] != 0 {
		return "", errInvalid
	}
	for _, v := range values[:len(values)-1] {
		if v == 0 {
			return "", errInvalid
		}
	}
	return windows.UTF16ToString(values), nil
}
