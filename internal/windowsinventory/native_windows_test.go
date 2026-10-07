//go:build windows

package windowsinventory

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeBufferStringBounds(t *testing.T) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint16(buf[2:4], 'A')
	if got, ok := bufferString(buf, (*uint16)(unsafe.Pointer(&buf[2]))); !ok || got != "A" {
		t.Fatal("valid native string rejected")
	}
	if _, ok := bufferString(buf, nil); ok {
		t.Fatal("nil native pointer accepted")
	}
	var outside uint16
	if _, ok := bufferString(buf, &outside); ok {
		t.Fatal("out-of-buffer pointer accepted")
	}
	if _, ok := bufferString(buf, (*uint16)(unsafe.Pointer(&buf[1]))); ok {
		t.Fatal("unaligned native pointer accepted")
	}
	for i := range buf {
		buf[i] = 1
	}
	if _, ok := bufferString(buf, (*uint16)(unsafe.Pointer(&buf[0]))); ok {
		t.Fatal("unterminated native string accepted")
	}
}
func TestNativeServiceStateMapping(t *testing.T) {
	for _, state := range []uint32{windows.SERVICE_STOPPED, windows.SERVICE_START_PENDING, windows.SERVICE_STOP_PENDING, windows.SERVICE_RUNNING, windows.SERVICE_CONTINUE_PENDING, windows.SERVICE_PAUSE_PENDING, windows.SERVICE_PAUSED} {
		if !validServiceState(serviceState(state)) {
			t.Fatal("known service state missing")
		}
	}
	if validServiceState(serviceState(99)) {
		t.Fatal("unknown service state accepted")
	}
}

// Only the explicit hosted read-only gate enables real metadata reads. Never
// print rows, hostnames, addresses or raw native errors, including on failure.
func TestNativeWindowsReadOnlyInventory(t *testing.T) {
	if os.Getenv("TRACEBOLT_WINDOWS_READONLY_NATIVE") != "1" {
		t.Skip("native Windows read-only gate is opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := Collect(ctx)
	if err != nil {
		t.Fatal("native Windows collection failed")
	}
	if r.Platform != "windows" || r.Schema != Schema || r.Hostname.Quality != "healthy" || len(r.Hostname.Rows) != 1 {
		t.Fatal("native identity observation unavailable")
	}
	if r.Memory.Quality != "healthy" || r.Disk.Quality != "healthy" {
		t.Fatal("native capacity observation unavailable")
	}
	if r.CPU.Quality != "healthy" || r.CPU.Value == nil || *r.CPU.Value < 0 || *r.CPU.Value > 100 {
		t.Fatal("native CPU interval unavailable")
	}
	found := false
	for _, p := range r.Processes.Rows {
		if p.PID == uint32(os.Getpid()) {
			found = true
		}
	}
	if !found || r.Processes.Quality != "healthy" {
		t.Fatal("own process absent from complete native snapshot")
	}
	if len(r.Services.Rows) == 0 || r.Services.Quality == "denied" || r.Services.Quality == "unknown" {
		t.Fatal("native service enumeration unavailable")
	}
	if len(r.Software.Rows) == 0 || len(r.Network.Rows) == 0 {
		t.Fatal("native software or interface enumeration unavailable")
	}
	if _, err := Encode(r); err != nil {
		t.Fatal("native bounded encoding failed")
	}
}
