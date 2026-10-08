//go:build !windows

package windowsconsole

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatformDoesNotPrompt(t *testing.T) {
	secret, err := ReadInvitation(context.Background(), func() error {
		t.Fatal("unsupported platform invoked prompt")
		return nil
	})
	if secret != nil || !errors.Is(err, ErrInput) || CategoryOf(err) != CategoryUnsupported {
		t.Fatal("unsupported platform did not fail closed")
	}
}
