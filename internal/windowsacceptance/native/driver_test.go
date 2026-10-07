package native

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type deniedGuard struct{ calls int }

func (g *deniedGuard) Check() bool { g.calls++; return false }
func fixtureDriver(t *testing.T) *Driver {
	t.Helper()
	d, err := New(Options{ServiceArtifact: "never-open-service", ControllerArtifact: "never-open-controller", ServiceSHA256: strings.Repeat("a", 64), ControllerSHA256: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal("inert constructor rejected valid values")
	}
	return d
}

// These tests do not call a Windows API, create state or key material, or touch
// the filesystem. The guard must refuse before platform dispatch on every OS.
func TestEveryDriverMutatorRequiresLiveGuardBeforePlatformDispatch(t *testing.T) {
	for _, name := range []string{"Provision", "Prepare", "Claim", "Start", "Probe", "Stop", "CleanupStop", "Uninstall", "Cleanup"} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDriver(t)
			g := &deniedGuard{}
			ctx := context.Background()
			var err error
			switch name {
			case "Provision":
				err = d.Provision(ctx, g)
			case "Prepare":
				err = d.Prepare(ctx, g, nil)
			case "Claim":
				err = d.Claim(ctx, g, nil, nil)
			case "Start":
				err = d.Start(ctx, g)
			case "Probe":
				err = d.Probe(ctx, g)
			case "Stop":
				err = d.Stop(ctx, g)
			case "CleanupStop":
				err = d.CleanupStop(ctx, g)
			case "Uninstall":
				err = d.Uninstall(ctx, g)
			case "Cleanup":
				err = d.Cleanup(ctx, g)
			}
			if err != ErrAcceptance || g.calls != 1 || d.Evidence().Reason != ReasonGuard || d.state != nil || d.receipt.InstallationID != "" {
				t.Fatal("guard did not stop operation before native dispatch")
			}
		})
	}
	if RunProbe(context.Background(), nil) != ErrAcceptance {
		t.Fatal("unguarded probe entered native dispatcher")
	}
}
func TestCanceledContextDoesNotConsultGrantOrNativeState(t *testing.T) {
	d := fixtureDriver(t)
	g := &deniedGuard{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.Provision(ctx, g) != ErrAcceptance || g.calls != 0 || d.Evidence().Reason != ReasonTimeout {
		t.Fatal("canceled call reached authority/native state")
	}
}
func TestConstructorAndFormattingAreInertAndRedacted(t *testing.T) {
	d := fixtureDriver(t)
	if d.state != nil || d.Evidence().Stage != StageIdle {
		t.Fatal("constructor entered native mode")
	}
	for _, v := range []any{d, d.options} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal("cannot encode redacted model")
		}
		for _, out := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), string(b)} {
			if strings.Contains(out, "never-open") || strings.Contains(out, strings.Repeat("a", 64)) {
				t.Fatal("opaque input formatting exposed artifact data")
			}
		}
	}
}
func TestConstructorRejectsInvalidArtifactBinding(t *testing.T) {
	for _, hash := range []string{"", strings.Repeat("A", 64), strings.Repeat("x", 64), strings.Repeat("a", 62)} {
		if _, err := New(Options{ServiceArtifact: "fixture", ControllerArtifact: "fixture", ServiceSHA256: hash, ControllerSHA256: strings.Repeat("b", 64)}); err != ErrAcceptance {
			t.Fatal("invalid hash admitted")
		}
	}
}
func TestEvidenceHasOnlyFiniteStagesReasonsAndBooleans(t *testing.T) {
	v := reflect.TypeOf(Evidence{})
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Type.Kind() != reflect.Bool && f.Type != reflect.TypeOf(StageIdle) && f.Type != reflect.TypeOf(ReasonNone) {
			t.Fatal("report expanded beyond finite evidence")
		}
	}
}
