//go:build windows && (amd64 || arm64)

package windowsresourcecontext

import "unsafe"

// Two-sided compile-time assertions cover both supported Windows target ABIs.
var _ [104 - int(unsafe.Sizeof(performanceInformation{}))]byte
var _ [int(unsafe.Sizeof(performanceInformation{})) - 104]byte
var _ [32 - int(unsafe.Sizeof(enumPageFileInformation{}))]byte
var _ [int(unsafe.Sizeof(enumPageFileInformation{})) - 32]byte
var _ [80 - int(unsafe.Offsetof(performanceInformation{}.PageSize))]byte
var _ [int(unsafe.Offsetof(performanceInformation{}.PageSize)) - 80]byte
