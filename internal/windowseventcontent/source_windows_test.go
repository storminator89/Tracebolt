//go:build windows

package windowseventcontent

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
			t.Fatal("unexpected native error taxonomy")
		}
	}
	for _, source := range []error{windows.ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND, windows.ERROR_FILE_NOT_FOUND, windows.ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND} {
		if !errors.Is(publisherError(source), ErrPublisherUnavailable) {
			t.Fatal("missing publisher misrepresented")
		}
	}
	for _, source := range []error{windows.ERROR_EVT_MESSAGE_NOT_FOUND, windows.ERROR_EVT_MESSAGE_ID_NOT_FOUND,
		windows.ERROR_EVT_UNRESOLVED_VALUE_INSERT, windows.ERROR_EVT_UNRESOLVED_PARAMETER_INSERT, windows.ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND,
		windows.ERROR_RESOURCE_DATA_NOT_FOUND, windows.ERROR_MUI_FILE_NOT_FOUND} {
		if !errors.Is(messageError(source), ErrMessageUnavailable) {
			t.Fatal("missing/partial message misrepresented")
		}
	}
}

// Ordinary Windows tests must never read actual host messages.
func TestNativeInvalidOrCanceledSelectionNeverReads(t *testing.T) {
	req := Request{Events: []Event{fixtureEvent("Security", 1)}}
	if _, err := Read(context.Background(), req); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("forbidden channel accepted")
	}
	req.Events[0].Channel = "System"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request proceeded")
	}
}
