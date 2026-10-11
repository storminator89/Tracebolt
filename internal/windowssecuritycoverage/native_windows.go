//go:build windows

package windowssecuritycoverage

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// Fixed public CLSID_WSCProductList, IWSCProductList/IWscProduct getters only.
// The SDK interfaces inherit IDispatch. No SecurityCenter2 WMI productState bit
// decoding, remediation path, GUID, timestamp, default-product or action API.
var productListID = windows.GUID{Data1: 0x17072f7b, Data2: 0x9abe, Data3: 0x4a74, Data4: [8]byte{0xa2, 0x61, 0x1e, 0xb7, 0x6b, 0x55, 0x10, 0x7a}}

func nativeAntivirus(ctx context.Context) (Antivirus, error) {
	if e := ctx.Err(); e != nil {
		return Antivirus{}, e
	}
	// Microsoft documents no Windows Server support. Do not mistake an empty or
	// failed Server product list for absent antivirus software.
	os := windows.RtlGetVersion()
	if os == nil || os.ProductType != 1 {
		return Antivirus{}, ErrUnsupported
	}
	list, close, e := openAutomation(ctx, &productListID)
	if e != nil {
		return Antivirus{}, e
	}
	defer close()
	initialized, e := list.invoke(ctx, "Initialize", dispatchMethod, intArgument(4)) // WSC_SECURITY_PROVIDER_ANTIVIRUS
	initialized.clear()
	if e != nil {
		return Antivirus{}, e
	}
	count, e := list.integer(ctx, "Count")
	if e != nil {
		return Antivirus{}, e
	}
	if count < 0 || count > 65535 {
		return Antivirus{}, ErrBounds
	}
	n := uint32(count)
	a := Antivirus{Quality: "observed", ReportedCount: &n, Rows: []Product{}}
	mark := func(e error) {
		if e != nil {
			a.Quality = "partial"
			if a.Reason == "" {
				a.Reason = SafeReason(e)
			}
		}
	}
	limit := int(count)
	if limit > MaxProducts {
		limit = MaxProducts
		mark(ErrBounds)
		a.Truncated = true
	}
	for i := 0; i < limit; i++ {
		if e := ctx.Err(); e != nil {
			return Antivirus{}, e
		}
		p := Product{Index: i, State: "unknown", SignatureStatus: "unknown"}
		item, e := list.objectValue(ctx, "Item", dispatchGet, intArgument(int32(i)))
		if e != nil {
			mark(e)
			a.Rows = append(a.Rows, p)
			continue
		}
		name, e := item.text(ctx, "ProductName", MaxProductNameUnits)
		if e == nil && !validName(name) {
			e = ErrMetadata
		}
		mark(e)
		if e == nil {
			p.Name = &name
		}
		state, e := item.integer(ctx, "ProductState")
		mark(e)
		if e == nil {
			switch state {
			case 0:
				p.State = "on"
			case 1:
				p.State = "off"
			case 2:
				p.State = "snoozed"
			case 3:
				p.State = "expired"
			default:
				mark(ErrMetadata)
			}
		}
		signature, e := item.integer(ctx, "SignatureStatus")
		mark(e)
		if e == nil {
			switch signature {
			case 0:
				p.SignatureStatus = "out-of-date"
			case 1:
				p.SignatureStatus = "up-to-date"
			default:
				mark(ErrMetadata)
			}
		}
		item.close()
		a.Rows = append(a.Rows, p)
	}
	return a, nil
}

var tbsDLL = windows.NewLazySystemDLL("tbs.dll")
var getDeviceInfo = tbsDLL.NewProc("Tbsi_GetDeviceInfo")

type tpmDeviceInfo struct{ StructVersion, TPMVersion, ReservedInterface, ReservedRevision uint32 }

func nativeTPM(ctx context.Context) (TPM, error) {
	if e := ctx.Err(); e != nil {
		return TPM{}, e
	}
	if getDeviceInfo.Find() != nil {
		return TPM{}, ErrUnsupported
	}
	// Fixed-size public device info only. Reserved fields are never exposed or
	// interpreted. No TBS context, TPM command, ownership or readiness request.
	info := tpmDeviceInfo{StructVersion: 2}
	result, _, _ := getDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(&info)
	if e := ctx.Err(); e != nil {
		return TPM{}, e
	}
	switch uint32(result) {
	case 0:
		return tpmInfo(info.TPMVersion), nil
	case 0x8028400f:
		return TPM{Quality: "observed", Presence: "not-found", Version: "unknown"}, nil
	case 0x80284012:
		return TPM{}, ErrDenied // TBS_E_ACCESS_DENIED
	default:
		return TPM{}, ErrUnavailable
	}
}
