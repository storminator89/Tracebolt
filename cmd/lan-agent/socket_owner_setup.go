package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/socketowner"
	"strconv"
	"strings"
)

type socketOwnerSetupOptions struct {
	mode, identity string
	ack            lanclient.SocketOwnerSetupAcknowledgements
}
type socketOwnerSetupHooks struct {
	identity  func(string) bool
	configure func(context.Context, string, []byte, lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error)
}

func defaultSocketOwnerSetupHooks() socketOwnerSetupHooks {
	return socketOwnerSetupHooks{identity: serviceIdentity, configure: lanclient.ConfigureSocketOwners}
}
func socketOwnerSetupNumericIdentity(value string) bool {
	ids := strings.Split(value, ":")
	if len(ids) != 2 {
		return false
	}
	for _, id := range ids {
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil || n == 0 || n == 1<<32-1 || strconv.FormatUint(n, 10) != id {
			return false
		}
	}
	return true
}

// Reserve the entire namespace before any ordinary sender, enrollment, helper
// or other setup dispatch. Shorthand, assignment, mixed modes and duplicates
// are deliberately not aliases. A malformed invocation performs no reads.
func socketOwnerSetupInvocation(args []string) (selected bool, options socketOwnerSetupOptions, valid bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--socket-owner-") || strings.HasPrefix(arg, "-socket-owner-") || strings.HasPrefix(arg, "--ack-socket-owner-") || strings.HasPrefix(arg, "-ack-socket-owner-") {
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
		case "--socket-owner-setup-capabilities", "--socket-owner-setup-identity", "--socket-owner-setup-preview", "--socket-owner-setup-initialize", "--socket-owner-setup-disable":
			if options.mode != "" {
				return true, options, false
			}
			options.mode = strings.TrimPrefix(arg, "--socket-owner-setup-")
		case "--service-identity":
			i++
			if i >= len(args) || !socketOwnerSetupNumericIdentity(args[i]) {
				return true, options, false
			}
			options.identity = args[i]
		case "--ack-socket-owner-metadata":
			options.ack.Metadata = true
		case "--ack-socket-owner-ptrace-risk":
			options.ack.PtraceRisk = true
		case "--ack-socket-owner-http-plaintext":
			options.ack.HTTPPlaintext = true
		default:
			return true, options, false
		}
	}
	switch options.mode {
	case "capabilities":
		valid = len(args) == 1
	case "identity", "preview", "disable":
		valid = options.identity != "" && options.ack == (lanclient.SocketOwnerSetupAcknowledgements{})
	case "initialize":
		valid = options.identity != "" && options.ack.Metadata && options.ack.PtraceRisk
	}
	return true, options, valid
}

type socketOwnerSetupCapabilities struct {
	SchemaVersion   string `json:"schemaVersion"`
	IdentityVersion string `json:"identityVersion"`
	ResultVersion   string `json:"resultVersion"`
	ConsentVersion  string `json:"consentVersion"`
	PolicyVersion   string `json:"policyVersion"`
	Scope           string `json:"scope"`
	MaxPolicyBytes  int    `json:"maxPolicyBytes"`
}

func runSocketOwnerSetup(ctx context.Context, options socketOwnerSetupOptions, valid bool, h socketOwnerSetupHooks, stdin io.Reader, stdout, stderr io.Writer) int {
	reject := func() int {
		fmt.Fprintln(stderr, "Tracebolt socket-owner setup rejected or incomplete; preserve local state and inspect the explicit mode and stopped service identity. Pending discard is not confirmed.")
		return 2
	}
	if !valid || ctx == nil || ctx.Err() != nil {
		return reject()
	}
	var result any
	if options.mode == "capabilities" {
		result = socketOwnerSetupCapabilities{"tracebolt.socket-owner-setup-capabilities.v1", lanclient.SocketOwnerSetupIdentityVersion,
			lanclient.SocketOwnerSetupResultVersion, lanclient.SocketOwnerConsentVersion, socketowner.PolicyVersion, socketowner.Scope, socketowner.MaxPolicyBytes}
	} else {
		if h.identity == nil || !h.identity(options.identity) || h.configure == nil {
			return reject()
		}
		var raw []byte
		if options.mode == "initialize" || options.mode == "disable" {
			if stdin == nil {
				return reject()
			}
			var err error
			raw, err = io.ReadAll(io.LimitReader(stdin, socketowner.MaxPolicyBytes+1))
			if err != nil || len(raw) == 0 || len(raw) > socketowner.MaxPolicyBytes {
				return reject()
			}
			p, err := socketowner.DecodePolicy(raw)
			if err != nil || p.Enabled != (options.mode == "initialize") {
				return reject()
			}
			expected := lanclient.SocketOwnerSetupAcknowledgements{}
			if options.mode == "initialize" {
				expected = lanclient.SocketOwnerSetupAcknowledgements{Metadata: true, PtraceRisk: true, HTTPPlaintext: p.TransportProfile == "http-test"}
			}
			if options.ack != expected {
				return reject()
			}
		}
		out, err := h.configure(ctx, options.mode, raw, options.ack)
		if err != nil {
			if errors.Is(err, lanclient.ErrSocketOwnerSetupDisableIncomplete) {
				fmt.Fprintln(stderr, "Tracebolt socket-owner disable incomplete: disabled consent was persisted; pending discard is not confirmed. Preserve state and keep the agent and helper stopped.")
				return 2
			}
			return reject()
		}
		result = out
	}
	// Marshal first: an oversized or invalid result cannot leak a partial object.
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 8192 {
		return reject()
	}
	raw = append(raw, '\n')
	if n, err := stdout.Write(raw); err != nil || n != len(raw) {
		return reject()
	}
	return 0
}
