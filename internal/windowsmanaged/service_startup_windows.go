//go:build windows

package windowsmanaged

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every native operation has a typed injected seam. Windows tests provide all
// functions, never loading a DLL or reading/changing a real host service.
type serviceStartupNativeAPI struct {
	openSCM      func(*uint16, *uint16, uint32) (windows.Handle, error)
	openService  func(windows.Handle, *uint16, uint32) (windows.Handle, error)
	queryConfig  func(windows.Handle, *windows.QUERY_SERVICE_CONFIG, uint32, *uint32) error
	queryConfig2 func(windows.Handle, uint32, *byte, uint32, *uint32) error
	close        func(windows.Handle) error
}

var serviceStartupSystemAPI = serviceStartupNativeAPI{
	openSCM:      windows.OpenSCManager,
	openService:  windows.OpenService,
	queryConfig:  windows.QueryServiceConfig,
	queryConfig2: windows.QueryServiceConfig2,
	close:        windows.CloseServiceHandle,
}

func serviceStartupNativeReader(ctx context.Context) (ServiceStartupReader, func(), error) {
	return serviceStartupNativeReaderUsing(ctx, serviceStartupSystemAPI)
}

func serviceStartupNativeError(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return ErrServiceStartupDenied
	}
	return ErrServiceStartupUnavailable
}

func serviceStartupNativeReaderUsing(ctx context.Context, api serviceStartupNativeAPI) (ServiceStartupReader, func(), error) {
	if ctx == nil || api.openSCM == nil || api.openService == nil || api.queryConfig == nil || api.queryConfig2 == nil || api.close == nil {
		return nil, nil, ErrServiceStartupInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Nil machine and database select local SCM only. CONNECT does not confer
	// enumeration, mutation, security-read or privilege-adjustment rights.
	manager, err := api.openSCM(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, serviceStartupNativeError(err)
	}
	if manager == 0 {
		return nil, nil, ErrServiceStartupUnavailable
	}
	closeManager := func() { _ = api.close(manager) }
	if err := ctx.Err(); err != nil {
		closeManager()
		return nil, nil, err
	}
	return func(ctx context.Context, name string) (ServiceStartupRow, error) {
		return readServiceStartupNative(ctx, manager, name, api)
	}, closeManager, nil
}

func readServiceStartupNative(ctx context.Context, manager windows.Handle, name string, api serviceStartupNativeAPI) (ServiceStartupRow, error) {
	if ctx == nil || !validText(name, true, MaxTextBytes) {
		return ServiceStartupRow{}, ErrServiceStartupInvalid
	}
	if err := ctx.Err(); err != nil {
		return ServiceStartupRow{}, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ServiceStartupRow{}, ErrServiceStartupInvalid
	}
	h, err := api.openService(manager, name16, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return ServiceStartupRow{}, serviceStartupNativeError(err)
	}
	if h == 0 {
		return ServiceStartupRow{}, ErrServiceStartupUnavailable
	}
	// This function returns only after closing the single owned service handle;
	// the caller cannot open the next service while this handle is still owned.
	defer api.close(h)
	if err := ctx.Err(); err != nil {
		return ServiceStartupRow{}, err
	}

	// QueryServiceConfigW's documented maximum is 8 KiB. One fixed allocation
	// and one call avoid an unbounded resize loop. Its aggregate buffer may hold
	// paths/accounts: never follow any pointer, log it or copy it into a row.
	buf := make([]byte, ServiceStartupMaxConfigBytes)
	defer func() { clear(buf); runtime.KeepAlive(buf) }()
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	var needed uint32
	err = api.queryConfig(h, config, uint32(len(buf)), &needed)
	// Read only typed scalar DWORDs. No string pointer, error-control field,
	// dependency, description, account or security descriptor is dereferenced.
	var startType, serviceType uint32
	if err == nil && needed <= uint32(len(buf)) {
		startType, serviceType = config.StartType, config.ServiceType
	}
	clear(buf)
	runtime.KeepAlive(buf)
	if e := ctx.Err(); e != nil {
		return ServiceStartupRow{}, e
	}
	if err != nil {
		return ServiceStartupRow{}, serviceStartupNativeError(err)
	}
	if needed > uint32(len(buf)) {
		return ServiceStartupRow{}, ErrServiceStartupUnavailable
	}

	// Ignore drivers and unexpected service types. User-service/instance and
	// interactive flags can qualify a Win32 type; no type is exported.
	const allowedServiceType = uint32(0x10 | 0x20 | 0x40 | 0x80 | 0x100)
	baseType := serviceType & windows.SERVICE_WIN32
	if (baseType != windows.SERVICE_WIN32_OWN_PROCESS && baseType != windows.SERVICE_WIN32_SHARE_PROCESS) || serviceType & ^allowedServiceType != 0 {
		return serviceStartupFailure("unknown"), nil
	}
	var mode string
	switch startType {
	case windows.SERVICE_AUTO_START:
		mode = "automatic"
	case windows.SERVICE_DEMAND_START:
		mode = "manual"
	case windows.SERVICE_DISABLED:
		mode = "disabled"
	default:
		return serviceStartupFailure("unknown"), nil
	}
	row := ServiceStartupRow{StartupMode: &mode, StartupQuality: "observed", DelayedAutoQuality: "not-applicable"}
	if mode != "automatic" {
		return row, nil
	}
	row.DelayedAutoQuality = "unavailable"
	if err := ctx.Err(); err != nil {
		return ServiceStartupRow{}, err
	}
	// SERVICE_DELAYED_AUTO_START_INFO contains just a BOOL, with no pointers.
	// Query this single level only, and only for a confirmed automatic service.
	var delayed uint32
	needed = 0
	err = api.queryConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&delayed)), uint32(unsafe.Sizeof(delayed)), &needed)
	if e := ctx.Err(); e != nil {
		return ServiceStartupRow{}, e
	}
	if err != nil {
		if errors.Is(serviceStartupNativeError(err), ErrServiceStartupDenied) {
			row.DelayedAutoQuality = "denied"
		}
		return row, nil
	}
	if needed > uint32(unsafe.Sizeof(delayed)) {
		return row, nil
	}
	value := delayed != 0
	row.DelayedAutoStart, row.DelayedAutoQuality = &value, "observed"
	return row, nil
}
