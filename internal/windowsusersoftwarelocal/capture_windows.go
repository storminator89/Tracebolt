//go:build windows

package windowsusersoftwarelocal

import (
	"context"
	"localrmm/internal/windowsusersoftware"
	"runtime"
	"time"
)

// This timeout is safe only inside the one-shot helper. On timeout the client
// exits without further native calls or submit retries; its main calls os.Exit.
func captureForeground(parent context.Context) windowsusersoftware.Capture {
	start := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, windowsusersoftware.CaptureTimeout)
	defer cancel()
	result := make(chan windowsusersoftware.Capture, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if !noThreadImpersonation() {
			result <- windowsusersoftware.Capture{StartedAt: start, FinishedAt: time.Now().UTC(), Reason: "access_denied"}
			return
		}
		result <- collectSources(ctx, readHKCU, readMSIX, start)
	}()
	select {
	case c := <-result:
		return c
	case <-ctx.Done():
		return windowsusersoftware.Capture{StartedAt: start, FinishedAt: time.Now().UTC(), Reason: failureStatus(ctx.Err())}
	}
}
