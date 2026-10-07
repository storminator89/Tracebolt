package windowspath

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRootDiagnosticKeepsCauseAndRedactsFormatting(t *testing.T) {
	secret := errors.New("private-device-path/native-error")
	err := rootRejected("root-open-other", secret)
	if !errors.Is(err, secret) || RootDiagnostic(fmt.Errorf("ignored wrapper: %w", err)) != "root-open-other" {
		t.Fatal("failure identity lost")
	}
	for _, out := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(out, "private") || strings.Contains(out, "native-error") {
			t.Fatal("failure formatting leaked native details")
		}
	}
	if RootDiagnostic(secret) != "" || RootDiagnostic(rootRejected("private-device-path", secret)) != "" || RootDiagnostic(nil) != "" {
		t.Fatal("unbounded diagnostic accepted")
	}
}
