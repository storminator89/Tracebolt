//go:build windows

package windowspackage

import (
	"context"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	job "localrmm/internal/windowssoftwarejob"
)

var msiDatabaseDLL = windows.NewLazySystemDLL("msi.dll")
var msiOpenDatabase = msiDatabaseDLL.NewProc("MsiOpenDatabaseW")
var msiCloseHandle = msiDatabaseDLL.NewProc("MsiCloseHandle")
var msiOpenView = msiDatabaseDLL.NewProc("MsiDatabaseOpenViewW")
var msiViewExecute = msiDatabaseDLL.NewProc("MsiViewExecute")
var msiViewFetch = msiDatabaseDLL.NewProc("MsiViewFetch")
var msiRecordString = msiDatabaseDLL.NewProc("MsiRecordGetStringW")
var msiRecordInteger = msiDatabaseDLL.NewProc("MsiRecordGetInteger")
var msiSummaryOpen = msiDatabaseDLL.NewProc("MsiGetSummaryInformationW")
var msiSummaryProperty = msiDatabaseDLL.NewProc("MsiSummaryInfoGetPropertyW")

// Only read-only database views and summary metadata are opened. This does not
// execute an MSI session, validate/repair an installed product or prove custom
// actions harmless, network-free or suitable for this endpoint.
func verifyMSIDatabase(ctx context.Context, path string, want job.Selection) (err error) {
	if cancelled(ctx) || path == "" || !job.ValidSelection(want) {
		return failure("msi-metadata")
	}
	var database uint32
	code, _, _ := msiOpenDatabase.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(path))), 0, uintptr(unsafe.Pointer(&database))) // MSIDBOPEN_READONLY
	if code != 0 || database == 0 {
		return failure("msi-database")
	}
	defer func() {
		c, _, _ := msiCloseHandle.Call(uintptr(database))
		if c != 0 && err == nil {
			err = failure("msi-close")
		}
	}()
	query := func(sql string, limit int, consume func(uint32) error) (err error) {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		var view uint32
		code, _, _ := msiOpenView.Call(uintptr(database), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(sql))), uintptr(unsafe.Pointer(&view)))
		if code != 0 || view == 0 {
			return failure("msi-query")
		}
		defer func() {
			c, _, _ := msiCloseHandle.Call(uintptr(view))
			if c != 0 && err == nil {
				err = failure("msi-close")
			}
		}()
		code, _, _ = msiViewExecute.Call(uintptr(view), 0)
		if code != 0 {
			return failure("msi-query")
		}
		for count := 0; ; count++ {
			if cancelled(ctx) {
				return failure("cancelled")
			}
			var row uint32
			code, _, _ = msiViewFetch.Call(uintptr(view), uintptr(unsafe.Pointer(&row)))
			if code == 259 {
				return nil
			}
			if code != 0 || row == 0 {
				return failure("msi-query")
			}
			if count >= limit {
				msiCloseHandle.Call(uintptr(row))
				return failure("msi-bounds")
			}
			e := consume(row)
			c, _, _ := msiCloseHandle.Call(uintptr(row))
			if e != nil {
				return e
			}
			if c != 0 {
				return failure("msi-close")
			}
		}
	}
	property := func(sql string) (string, error) {
		var out string
		count := 0
		e := query(sql, 1, func(row uint32) error { count++; s, e := msiString(row, 1, 240); out = s; return e })
		if e != nil || count != 1 {
			return "", failure("msi-property")
		}
		return out, nil
	}
	for _, field := range []struct{ query, want string }{
		{"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'", want.ProductCode},
		{"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductVersion'", want.Version},
		{"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'", want.Name},
		{"SELECT `Value` FROM `Property` WHERE `Property` = 'ALLUSERS'", "1"},
	} {
		got, e := property(field.query)
		if e != nil || got != field.want {
			return failure("msi-property")
		}
	}
	if e := query("SELECT `Value` FROM `Property` WHERE `Property` = 'MSIINSTALLPERUSER'", 1, func(row uint32) error {
		s, e := msiString(row, 1, 8)
		if e != nil || s != "" {
			return failure("msi-per-user")
		}
		return nil
	}); e != nil {
		return e
	}
	// No package-authored property may implicitly supply an upgrade, repair,
	// transform or patch. Custom actions still require package-specific review.
	for _, sql := range []string{
		"SELECT `Value` FROM `Property` WHERE `Property` = 'TRANSFORMS'",
		"SELECT `Value` FROM `Property` WHERE `Property` = 'PATCH'",
		"SELECT `Value` FROM `Property` WHERE `Property` = 'REINSTALL'",
		"SELECT `Value` FROM `Property` WHERE `Property` = 'REMOVE'",
	} {
		if e := query(sql, 1, func(uint32) error { return failure("msi-action-property") }); e != nil {
			return e
		}
	}
	var summary uint32
	code, _, _ = msiSummaryOpen.Call(uintptr(database), 0, 0, uintptr(unsafe.Pointer(&summary)))
	if code != 0 || summary == 0 {
		return failure("msi-summary")
	}
	defer func() {
		c, _, _ := msiCloseHandle.Call(uintptr(summary))
		if c != 0 && err == nil {
			err = failure("msi-close")
		}
	}()
	text := func(property uint32) (string, error) {
		var kind uint32
		var integer int32
		var stamp windows.Filetime
		var buffer [256]uint16
		n := uint32(len(buffer))
		c, _, _ := msiSummaryProperty.Call(uintptr(summary), uintptr(property), uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&integer)), uintptr(unsafe.Pointer(&stamp)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&n)))
		if c != 0 || kind != 30 || n >= uint32(len(buffer)) {
			return "", failure("msi-summary")
		}
		return windows.UTF16ToString(buffer[:n]), nil
	}
	number := func(property uint32) (int32, error) {
		var kind uint32
		var integer int32
		var n uint32
		c, _, _ := msiSummaryProperty.Call(uintptr(summary), uintptr(property), uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&integer)), 0, 0, uintptr(unsafe.Pointer(&n)))
		if c != 0 || kind != 3 {
			return 0, failure("msi-summary")
		}
		return integer, nil
	}
	template, e := text(7)
	if e != nil || strings.Split(template, ";")[0] != "x64" {
		return failure("msi-architecture")
	}
	packageCode, e := text(9)
	if e != nil || packageCode != want.PackageCode {
		return failure("msi-package-code")
	}
	schema, e := number(14)
	if e != nil || schema < 200 {
		return failure("msi-schema")
	}
	wordCount, e := number(15)
	if e != nil || wordCount != 2 && wordCount != 3 {
		return failure("msi-source-layout")
	}
	tables := map[string]bool{}
	if e = query("SELECT `Name` FROM `_Tables`", 128, func(row uint32) error {
		name, e := msiString(row, 1, 72)
		if e != nil {
			return e
		}
		tables[name] = true
		return nil
	}); e != nil {
		return e
	}
	if synchronousMSIRequired(ctx) && tables["CustomAction"] {
		if e = query("SELECT `Type` FROM `CustomAction`", 4096, func(row uint32) error {
			value, _, _ := msiRecordInteger.Call(uintptr(row), 1)
			if !synchronousCustomActionType(int32(value)) {
				return failure("msi-asynchronous-custom-action")
			}
			return nil
		}); e != nil {
			return e
		}
	}
	if tables["Upgrade"] {
		if e = query("SELECT `UpgradeCode` FROM `Upgrade`", 1, func(uint32) error { return failure("msi-upgrade") }); e != nil {
			return e
		}
	}
	if !tables["Media"] || !tables["File"] {
		return failure("msi-source-layout")
	}
	streams := map[string]bool{}
	if e = query("SELECT `Name` FROM `_Streams`", 256, func(row uint32) error {
		name, e := msiString(row, 1, 72)
		if e != nil {
			return e
		}
		streams[name] = true
		return nil
	}); e != nil {
		return e
	}
	media := 0
	lastSequence := int32(0)
	if e = query("SELECT `Cabinet`, `LastSequence` FROM `Media` ORDER BY `DiskId`", 64, func(row uint32) error {
		cab, e := msiString(row, 1, 72)
		if e != nil || len(cab) < 2 || cab[0] != '#' || !streams[cab[1:]] {
			return failure("msi-external-source")
		}
		n, _, _ := msiRecordInteger.Call(uintptr(row), 2)
		seq := int32(n)
		if seq <= lastSequence {
			return failure("msi-source-layout")
		}
		lastSequence = seq
		media++
		return nil
	}); e != nil {
		return e
	}
	files := 0
	if e = query("SELECT `Attributes`, `Sequence` FROM `File`", 4096, func(row uint32) error {
		attrs, _, _ := msiRecordInteger.Call(uintptr(row), 1)
		seq, _, _ := msiRecordInteger.Call(uintptr(row), 2)
		if int32(attrs) < 0 || attrs&8192 != 0 || int32(seq) <= 0 || int32(seq) > lastSequence {
			return failure("msi-external-source")
		}
		files++
		return nil
	}); e != nil {
		return e
	}
	if media == 0 || files == 0 {
		return failure("msi-source-layout")
	}
	if cancelled(ctx) {
		return failure("cancelled")
	}
	if synchronousMSIRequired(ctx) {
		return verifyCoordinatedRebootClear(ctx)
	}
	return nil
}
func msiString(row uint32, column uint32, limit int) (string, error) {
	buffer := make([]uint16, limit+1)
	n := uint32(len(buffer))
	c, _, _ := msiRecordString.Call(uintptr(row), uintptr(column), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&n)))
	if c != 0 || n > uint32(limit) {
		return "", failure("msi-string")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

// Fresh fixed-key evidence is required for each coordinated MSI preparation and
// final package recheck. Read value presence/size only, never path-bearing data.
func verifyCoordinatedRebootClear(ctx context.Context) error {
	for _, path := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`} {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		var key windows.Handle
		err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(path), 0, windows.KEY_QUERY_VALUE|windows.KEY_WOW64_64KEY, &key)
		if err == nil {
			_ = windows.RegCloseKey(key)
			return failure("msi-reboot-pending")
		}
		if err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return failure("msi-reboot-unknown")
		}
	}
	var key windows.Handle
	if windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(`SYSTEM\CurrentControlSet\Control\Session Manager`), 0, windows.KEY_QUERY_VALUE|windows.KEY_WOW64_64KEY, &key) != nil {
		return failure("msi-reboot-unknown")
	}
	var kind, size uint32
	err := windows.RegQueryValueEx(key, windows.StringToUTF16Ptr("PendingFileRenameOperations"), nil, &kind, nil, &size)
	closeErr := windows.RegCloseKey(key)
	if closeErr != nil || err != windows.ERROR_FILE_NOT_FOUND && (err != nil || kind != windows.REG_MULTI_SZ || size > 4) {
		return failure("msi-reboot-pending-or-unknown")
	}
	if cancelled(ctx) {
		return failure("cancelled")
	}
	return nil
}
