package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/actionhelper"
	"localrmm/internal/lanclient"
	"strings"
	"testing"
)

func TestActionSetupExclusiveSelection(t *testing.T) {
	for _, args := range [][]string{
		{"--action-setup-capabilities"}, {"--action-setup-initialize"},
		{"--action-setup-identity", "--config", "/fixture/agent.json", "--service-identity", "1234:1234"},
		{"--service-identity", "1234:1234", "--action-setup-readiness", "--config", "/fixture/agent.json"},
		{"--action-setup-check-target", "--review", "/fixture/review.json"},
	} {
		if selected, _, valid := actionSetupInvocation(args); !selected || !valid {
			t.Fatalf("valid setup mode rejected: %q", args)
		}
	}
	for _, args := range [][]string{
		{"--action-setup-capabilities", "--config", "/private"}, {"-action-setup-capabilities"},
		{"--action-setup-capabilities=true"}, {"--action-setup-initialize=false"},
		{"--action-setup-identity", "--config", "/private"},
		{"--action-setup-identity", "--config", "/private", "--service-identity", "1234:1234", "--foreground"},
		{"--action-setup-identity", "--config", "/private", "--service-identity", "1234:1234", "--config", "/private"},
		{"--action-setup-check-target", "--review", "/private", "--action-helper"},
		{"--action-setup-capabilities", "--action-setup-initialize"},
		{"--action-setup-check-target", "--review"}, {"--action-setup-unknown"},
	} {
		selected, options, valid := actionSetupInvocation(args)
		if !selected || valid {
			t.Fatalf("mixed/invalid mode accepted: %q", args)
		}
		var out, errs bytes.Buffer
		if runActionSetup(context.Background(), options, valid, actionSetupHooks{}, &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("invalid mode reached private operation")
		}
	}
	if selected, _, _ := actionSetupInvocation([]string{"--config", "/normal/agent.json", "--foreground"}); selected {
		t.Fatal("ordinary sender intercepted")
	}
}

func TestActionSetupCapabilitiesIsInert(t *testing.T) {
	var out, errs bytes.Buffer
	if runActionSetup(context.Background(), actionSetupOptions{mode: "--action-setup-capabilities"}, true, actionSetupHooks{}, &out, &errs) != 0 {
		t.Fatal(errs.String())
	}
	var result actionSetupCapabilities
	if json.Unmarshal(out.Bytes(), &result) != nil || result.IdentityVersion != lanclient.ActionSetupIdentityVersion || result.Action != "service.try-restart" || result.StartedVersion != actionhelper.SetupStartedVersion {
		t.Fatal("bad public schema projection", out.String())
	}
}

func TestActionSetupIdentityGuardPrecedesReads(t *testing.T) {
	for _, mode := range []string{"--action-setup-identity", "--action-setup-readiness"} {
		var out, errs bytes.Buffer
		hooks := actionSetupHooks{identity: func(string) bool { return false },
			inspect: func(string) (lanclient.ActionSetupIdentity, error) {
				t.Fatal("identity bypass")
				return lanclient.ActionSetupIdentity{}, nil
			},
			readiness: func(context.Context, string) (lanclient.ActionSetupReadiness, error) {
				t.Fatal("identity bypass")
				return lanclient.ActionSetupReadiness{}, nil
			}}
		if runActionSetup(context.Background(), actionSetupOptions{mode: mode, path: "/private", identity: "0:0"}, true, hooks, &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("rejected identity returned metadata")
		}
	}
}

func TestActionSetupRoutesOnlyExplicitOperationAndRedactsFailure(t *testing.T) {
	for _, mode := range []string{"--action-setup-identity", "--action-setup-readiness", "--action-setup-initialize", "--action-setup-check-target"} {
		for _, fail := range []bool{false, true} {
			calls := []string{}
			out, errs := &bytes.Buffer{}, &bytes.Buffer{}
			err := error(nil)
			if fail {
				err = errors.New("PRIVATE KEY OR RAW CONFIG")
			}
			hooks := actionSetupHooks{identity: func(string) bool { return true },
				inspect: func(string) (lanclient.ActionSetupIdentity, error) {
					calls = append(calls, "--action-setup-identity")
					return lanclient.ActionSetupIdentity{}, err
				},
				readiness: func(context.Context, string) (lanclient.ActionSetupReadiness, error) {
					calls = append(calls, "--action-setup-readiness")
					return lanclient.ActionSetupReadiness{}, err
				},
				initialize: func(context.Context) error { calls = append(calls, "--action-setup-initialize"); return err },
				target: func(context.Context, string) (actionhelper.SetupTargetResult, error) {
					calls = append(calls, "--action-setup-check-target")
					return actionhelper.SetupTargetResult{}, err
				}}
			code := runActionSetup(context.Background(), actionSetupOptions{mode: mode}, true, hooks, out, errs)
			if len(calls) != 1 || calls[0] != mode || (code != 0) != fail || strings.Contains(errs.String()+out.String(), "PRIVATE") || fail && out.Len() != 0 {
				t.Fatal(mode, calls, code, out.String(), errs.String())
			}
		}
	}
}
