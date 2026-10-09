//go:build !windows

package windowssetupui

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedRunNeverCallsHooks(t *testing.T) {
	fail := func() { t.Fatal("non-Windows UI invoked a hook") }
	h := Hooks{Preview: func([]byte) (TrustPreview, error) { fail(); return TrustPreview{}, nil }, Install: func(context.Context, []byte, bool, func(string)) error { fail(); return nil }, Uninstall: func(context.Context, func(string)) error { fail(); return nil }}
	if err := Run(Config{}, h); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unexpected unsupported result %v", err)
	}
}
