package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	"strings"
)

type actionSetupOptions struct {
	mode, path, identity, review string
}

type actionSetupHooks struct {
	identity   func(string) bool
	inspect    func(string) (lanclient.ActionSetupIdentity, error)
	readiness  func(context.Context, string) (lanclient.ActionSetupReadiness, error)
	initialize func(context.Context) error
	target     func(context.Context, string) (actionhelper.SetupTargetResult, error)
}

func defaultActionSetupHooks() actionSetupHooks {
	return actionSetupHooks{identity: serviceIdentity, inspect: lanclient.ReadActionSetupIdentity,
		readiness: lanclient.CheckActionSetupReadiness, initialize: actionhelper.RunSetupInitialize,
		target: actionhelper.CheckSetupTargetFile}
}

// Reserved setup modes are dispatched before normal flag parsing and all
// reporting/enrollment paths. Duplicate flags, assignments, shorthand, extra
// arguments and combinations with another mode reject before private reads.
func actionSetupInvocation(args []string) (selected bool, options actionSetupOptions, valid bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--action-setup-") || strings.HasPrefix(arg, "-action-setup-") {
			selected = true
		}
	}
	if !selected {
		return false, options, false
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if seen[arg] {
			return true, options, false
		}
		seen[arg] = true
		switch arg {
		case "--action-setup-capabilities", "--action-setup-identity", "--action-setup-readiness", "--action-setup-initialize", "--action-setup-check-target":
			if options.mode != "" {
				return true, options, false
			}
			options.mode = arg
		case "--config", "--service-identity", "--review":
			i++
			if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return true, options, false
			}
			switch arg {
			case "--config":
				options.path = args[i]
			case "--service-identity":
				options.identity = args[i]
			case "--review":
				options.review = args[i]
			}
		default:
			return true, options, false
		}
	}
	switch options.mode {
	case "--action-setup-capabilities", "--action-setup-initialize":
		valid = len(args) == 1
	case "--action-setup-identity", "--action-setup-readiness":
		valid = len(args) == 5 && options.path != "" && options.identity != "" && options.review == ""
	case "--action-setup-check-target":
		valid = len(args) == 3 && options.review != "" && options.path == "" && options.identity == ""
	}
	return true, options, valid
}

type actionSetupCapabilities struct {
	SchemaVersion             string `json:"schemaVersion"`
	IdentityVersion           string `json:"identityVersion"`
	ReadinessVersion          string `json:"readinessVersion"`
	TargetVersion             string `json:"targetVersion"`
	HelperPolicyVersion       string `json:"helperPolicyVersion"`
	ClientPolicyVersion       string `json:"clientPolicyVersion"`
	HelperCapabilitiesVersion string `json:"helperCapabilitiesVersion"`
	IntentVersion             string `json:"intentVersion"`
	StartedVersion            string `json:"startedVersion"`
	Action                    string `json:"action"`
}

func runActionSetup(ctx context.Context, options actionSetupOptions, valid bool, hooks actionSetupHooks, stdout, stderr io.Writer) int {
	reject := func() int {
		fmt.Fprintln(stderr, "Tracebolt action setup rejected; no action was submitted. Inspect the explicit mode and protected local setup state.")
		return 2
	}
	if !valid || ctx == nil || ctx.Err() != nil {
		return reject()
	}
	var result any
	var err error
	switch options.mode {
	case "--action-setup-capabilities":
		result = actionSetupCapabilities{SchemaVersion: "tracebolt.action-setup-capabilities.v1",
			IdentityVersion: lanclient.ActionSetupIdentityVersion, ReadinessVersion: lanclient.ActionSetupReadinessVersion,
			TargetVersion: actionhelper.SetupTargetVersion, HelperPolicyVersion: actionhelper.PolicyVersion,
			ClientPolicyVersion: lanclient.ActionClientPolicyVersion, HelperCapabilitiesVersion: actionhelper.CapabilitiesVersion,
			IntentVersion: actionhelper.SetupIntentVersion, StartedVersion: actionhelper.SetupStartedVersion, Action: actionpermit.TryRestartService}
	case "--action-setup-identity", "--action-setup-readiness":
		if hooks.identity == nil || !hooks.identity(options.identity) {
			return reject()
		}
		if options.mode == "--action-setup-identity" && hooks.inspect != nil {
			result, err = hooks.inspect(options.path)
		} else if options.mode == "--action-setup-readiness" && hooks.readiness != nil {
			result, err = hooks.readiness(ctx, options.path)
		} else {
			return reject()
		}
	case "--action-setup-initialize":
		if hooks.initialize == nil {
			return reject()
		}
		err = hooks.initialize(ctx)
		result = struct {
			SchemaVersion string `json:"schemaVersion"`
			Initialized   bool   `json:"initialized"`
		}{"tracebolt.action-setup-initialized.v1", true}
	case "--action-setup-check-target":
		if hooks.target == nil {
			return reject()
		}
		result, err = hooks.target(ctx, options.review)
	default:
		return reject()
	}
	if err != nil || json.NewEncoder(stdout).Encode(result) != nil {
		return reject()
	}
	return 0
}
