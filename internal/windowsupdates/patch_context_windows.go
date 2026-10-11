//go:build windows

package windowsupdates

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowspatchcontext"
	"unsafe"
)

// CLSID_SystemInformation from the Windows SDK wuapi.h. Like UpdateSession,
// activation is fixed in-process and occurs only after the existing token guard.
var systemInformationID = windows.GUID{Data1: 0xc01b9ba0, Data2: 0xbea7, Data3: 0x41ba, Data4: [8]byte{0xb6, 0x04, 0xd0, 0xa3, 0x6f, 0x46, 0x91, 0x33}}

type nativePatchSource struct{ source *nativeSource }
type nativeHistoryRows struct{ rows *automation }

func openPatchNative(ctx context.Context) (windowspatchcontext.Source, error) {
	s, e := openNative(ctx)
	if e != nil {
		return nil, patchError(e)
	}
	return &nativePatchSource{source: s.(*nativeSource)}, nil
}
func (s *nativePatchSource) Close() { s.source.Close() }
func (s *nativePatchSource) SetOnline(ctx context.Context, v bool) error {
	return patchError(s.source.SetOnline(ctx, v))
}
func (s *nativePatchSource) Online(ctx context.Context) (bool, error) {
	v, e := s.source.Online(ctx)
	return v, patchError(e)
}
func (s *nativePatchSource) SetAutomaticUpgrade(ctx context.Context, v bool) error {
	return patchError(s.source.SetAutomaticUpgrade(ctx, v))
}
func (s *nativePatchSource) AutomaticUpgrade(ctx context.Context) (bool, error) {
	v, e := s.source.AutomaticUpgrade(ctx)
	return v, patchError(e)
}
func (s *nativePatchSource) RebootRequired(ctx context.Context) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	var ptr *dispatchObject
	hr, _, _ := coCreateInstance.Call(uintptr(unsafe.Pointer(&systemInformationID)), 0, 1, uintptr(unsafe.Pointer(&dispatchID)), uintptr(unsafe.Pointer(&ptr)))
	if e := hrError(hr); e != nil {
		return false, patchError(e)
	}
	if ptr == nil {
		return false, windowspatchcontext.ErrUnavailable
	}
	a := &automation{object: ptr}
	defer a.close()
	v, e := a.boolean(ctx, "RebootRequired")
	return v, patchError(e)
}
func (s *nativePatchSource) Total(ctx context.Context) (int32, error) {
	v, e := s.source.searcher.invoke(ctx, "GetTotalHistoryCount", dispatchMethod)
	if e != nil {
		return 0, patchError(e)
	}
	defer v.clear()
	if v.kind != vtI4 {
		return 0, windowspatchcontext.ErrMetadata
	}
	return int32(uint32(v.data[0])), nil
}
func (s *nativePatchSource) Query(ctx context.Context, count int32) (windowspatchcontext.HistoryRows, error) {
	if count <= 0 || count > windowspatchcontext.MaxRows {
		return nil, windowspatchcontext.ErrInvalid
	}
	// IDispatch arguments are right-to-left: count, then fixed startIndex=0.
	obj, e := s.source.searcher.objectValue(ctx, "QueryHistory", dispatchMethod, intArgument(count), intArgument(0))
	if e != nil {
		return nil, patchError(e)
	}
	return &nativeHistoryRows{obj}, nil
}
func (r *nativeHistoryRows) Close() { r.rows.close() }
func (r *nativeHistoryRows) Count(ctx context.Context) (int32, error) {
	v, e := r.rows.integer(ctx, "Count")
	return v, patchError(e)
}
func (r *nativeHistoryRows) Item(ctx context.Context, index int32) (windowspatchcontext.Entry, error) {
	zero := windowspatchcontext.Entry{}
	if index < 0 || index >= windowspatchcontext.MaxRows {
		return zero, windowspatchcontext.ErrInvalid
	}
	a, e := r.rows.objectValue(ctx, "Item", dispatchGet, intArgument(index))
	if e != nil {
		return zero, patchError(e)
	}
	defer a.close()
	identity, e := a.objectValue(ctx, "UpdateIdentity", dispatchGet)
	if e != nil {
		return zero, patchError(e)
	}
	defer identity.close()
	id, e := identity.text(ctx, "UpdateID", 36)
	if e != nil {
		return zero, patchError(e)
	}
	revision, e := identity.integer(ctx, "RevisionNumber")
	if e != nil {
		return zero, patchError(e)
	}
	if revision < 0 {
		return zero, windowspatchcontext.ErrMetadata
	}
	title, e := a.text(ctx, "Title", MaxNativeStringUnits)
	if e != nil {
		return zero, patchError(e)
	}
	operation, e := a.integer(ctx, "Operation")
	if e != nil {
		return zero, patchError(e)
	}
	if operation < 1 || operation > 2 {
		return zero, windowspatchcontext.ErrMetadata
	}
	result, e := a.integer(ctx, "ResultCode")
	if e != nil {
		return zero, patchError(e)
	}
	if result < 0 || result > 5 {
		return zero, windowspatchcontext.ErrMetadata
	}
	code, e := a.integer(ctx, "HResult")
	if e != nil {
		return zero, patchError(e)
	}
	date, e := a.invoke(ctx, "Date", dispatchGet)
	if e != nil {
		return zero, patchError(e)
	}
	defer date.clear()
	if date.kind != 7 {
		return zero, windowspatchcontext.ErrMetadata
	}
	at, e := patchDate(*(*float64)(unsafe.Pointer(&date.data[0])))
	if e != nil {
		return zero, e
	}
	return windowspatchcontext.Entry{Index: uint32(index), UpdateID: id, Revision: uint32(revision), Title: title, OccurredAt: at, Operation: []string{"installation", "uninstallation"}[operation-1], Result: []string{"not-started", "in-progress", "succeeded", "succeeded-with-errors", "failed", "aborted"}[result], HResult: fmt.Sprintf("%08x", uint32(code))}, nil
}
