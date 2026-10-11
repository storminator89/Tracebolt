//go:build windows

package windowsfullservices

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This executable stage is deliberately absent from every existing native
// workflow. A separately approved artifact/target/account invocation is needed.
// Metadata stays in memory; no service names or native errors reach test output.
func TestNativeFullServicesCallerVisibleEnumeration(t *testing.T) {
	if os.Getenv("TRACEBOLT_FULL_SERVICES_NATIVE") == "" {
		t.Skip("separate complete-services native scope is opt-in")
	}
	if !fullServicesNativeGate(os.Getenv, time.Now().UTC(), fullServicesNativeSource) {
		t.Fatal("complete-services native authorization binding rejected")
	}
	token := windows.GetCurrentProcessToken()
	user, e := token.GetTokenUser()
	if e != nil || !user.User.Sid.IsWellKnown(windows.WinLocalServiceSid) {
		t.Fatal("complete-services native caller must be LocalService")
	}
	ctx, cancel := context.WithTimeout(context.Background(), CaptureTimeout)
	defer cancel()
	capture, e := Collect(ctx)
	if e != nil || !capture.Complete || capture.Reason != "" || len(capture.Rows) == 0 {
		t.Fatal("complete caller-visible native enumeration unavailable")
	}
	if !fullServicesNativeGate(os.Getenv, time.Now().UTC(), fullServicesNativeSource) {
		t.Fatal("complete-services native authority expired")
	}
	if capture.FinishedAt.Before(capture.StartedAt) || capture.FinishedAt.Sub(capture.StartedAt) > CaptureTimeout || len(capture.Rows) > MaxRows {
		t.Fatal("complete-services native capture exceeded contract")
	}
	if _, size, e := RowsDigest(capture.Rows); e != nil || size > MaxSourceBytes {
		t.Fatal("complete-services native row contract failed")
	}
}
