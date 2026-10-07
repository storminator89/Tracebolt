//go:build windows

package windowsevents

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeErrorTaxonomy(t *testing.T) {
	for _, tt := range []struct{ source, want error }{
		{windows.ERROR_ACCESS_DENIED, ErrAccessDenied}, {windows.ERROR_TIMEOUT, context.DeadlineExceeded},
		{windows.ERROR_CANCELLED, context.Canceled}, {windows.ERROR_EVT_CHANNEL_NOT_FOUND, ErrUnavailable},
		{windows.ERROR_SERVICE_NOT_ACTIVE, ErrUnavailable}, {windows.ERROR_INVALID_DATA, ErrReadFailed},
	} {
		if !errors.Is(nativeError(tt.source), tt.want) {
			t.Fatal("unexpected native error mapping")
		}
	}
}

func TestNativeRejectsBeforeReading(t *testing.T) {
	if _, err := Collect(context.Background(), []string{"Security"}, 1); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("forbidden native channel accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx, []string{"System"}, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled native request proceeded")
	}
}
