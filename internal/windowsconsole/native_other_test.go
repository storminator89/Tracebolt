//go:build !windows

package windowsconsole

import (
	"context"
	"testing"
)

func TestUnsupportedPlatformDoesNotPrompt(t *testing.T) {
	secret, err := ReadInvitation(context.Background(), func() error {
		t.Fatal("unsupported platform invoked prompt")
		return nil
	})
	if secret != nil || err != ErrInput {
		t.Fatal("unsupported platform did not fail closed")
	}
}
