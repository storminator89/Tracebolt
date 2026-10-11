//go:build windows

package windowseventhistory

import (
	"context"
	"golang.org/x/sys/windows"
	"testing"
)

func TestNativeRejectsBeforeRead(t *testing.T) {
	s := fixtureSearch()
	s.Channel = "Security"
	if _, e := Read(context.Background(), Request{Search: &s}); e != ErrInvalidInput {
		t.Fatal("unsupported native channel accepted")
	}
	s = fixtureSearch()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Read(ctx, Request{Search: &s}); e != context.Canceled {
		t.Fatal("canceled native search ran")
	}
}
func TestNativeTaxonomy(t *testing.T) {
	if nativeError(windows.ERROR_ACCESS_DENIED) != ErrAccessDenied || nativeError(windows.ERROR_EVT_CHANNEL_NOT_FOUND) != ErrUnavailable {
		t.Fatal("native taxonomy changed")
	}
}
