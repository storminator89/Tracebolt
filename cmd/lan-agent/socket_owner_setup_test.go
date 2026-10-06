package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/socketowner"
	"os"
	"strings"
	"testing"
)

func socketSetupCLIPolicy(profile string, enabled bool) socketowner.Policy {
	origin := "https://fixture.test"
	if profile == "http-test" {
		origin = "http://fixture.test"
	}
	return socketowner.Policy{Version: socketowner.PolicyVersion, Scope: socketowner.Scope, SenderBinding: strings.Repeat("a", 64), ManagerOrigin: origin, TransportProfile: profile, CollectionProfile: "managed-operations-v3", AgentUID: 1234, AgentGID: 1234, HelperUID: 1235, HelperGID: 1235, Epoch: strings.Repeat("e", 64), Enabled: enabled, MetadataAcknowledged: true, PtraceRiskAcknowledged: true, HTTPAcknowledged: profile == "http-test"}
}
func socketSetupCLIArgs(mode string, http bool) []string {
	args := []string{"--socket-owner-setup-" + mode}
	if mode != "capabilities" {
		args = append(args, "--service-identity", "1234:1234")
	}
	if mode == "initialize" {
		args = append(args, "--ack-socket-owner-metadata", "--ack-socket-owner-ptrace-risk")
		if http {
			args = append(args, "--ack-socket-owner-http-plaintext")
		}
	}
	return args
}

type socketSetupPanicReader struct{ t *testing.T }

func (r socketSetupPanicReader) Read([]byte) (int, error) {
	r.t.Fatal("unexpected stdin read")
	return 0, io.EOF
}
func TestSocketOwnerSetupCLIExclusiveParser(t *testing.T) {
	for _, mode := range []string{"capabilities", "identity", "preview", "initialize", "disable"} {
		args := socketSetupCLIArgs(mode, false)
		if selected, o, valid := socketOwnerSetupInvocation(args); !selected || !valid || o.mode != mode {
			t.Fatal("valid fixed mode rejected", args)
		}
	}
	good := socketSetupCLIArgs("initialize", true)
	invalid := [][]string{
		{"--socket-owner-setup-preview"}, {"--socket-owner-setup-capabilities", "--service-identity", "1234:1234"},
		{"-socket-owner-setup-capabilities"}, {"--socket-owner-setup-capabilities=true"}, {"--socket-owner-setup-preview=false"},
		{"--socket-owner-setup-unknown"}, {"--ack-socket-owner-metadata"}, {"--socket-owner-setup-capabilities", "--socket-owner-setup-preview"},
		{"--socket-owner-setup-preview", "--service-identity=1234:1234"}, {"--socket-owner-setup-preview", "--service-identity"},
		{"--socket-owner-setup-preview", "--service-identity", "0:0"}, {"--socket-owner-setup-preview", "--service-identity", "01234:1234"},
		{"--socket-owner-setup-preview", "--service-identity", "+1234:1234"}, {"--socket-owner-setup-preview", "--service-identity", "1234:4294967295"},
		{"--socket-owner-setup-initialize", "--service-identity", "1234:1234"},
	}
	for _, extra := range []string{"--foreground", "--action-helper", "--action-setup-capabilities", "--journal-reader", "--journal-capabilities", "--pending-service", "--config", "/private/agent.json", "--review", "--ack-socket-owner-ptrace-risk", "--socket-owner-setup-disable", "extra"} {
		invalid = append(invalid, append(append([]string{}, good...), extra))
	}
	for _, mode := range []string{"identity", "preview", "disable"} {
		invalid = append(invalid, append(socketSetupCLIArgs(mode, false), "--ack-socket-owner-metadata"))
	}
	for _, args := range invalid {
		selected, o, valid := socketOwnerSetupInvocation(args)
		if !selected || valid {
			t.Fatal("invalid/mixed mode admitted", args)
		}
		var out, errs bytes.Buffer
		if runSocketOwnerSetup(context.Background(), o, valid, socketOwnerSetupHooks{}, socketSetupPanicReader{t}, &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("invalid invocation read state")
		}
	}
	if selected, _, _ := socketOwnerSetupInvocation([]string{"--config", "/ordinary/config", "--foreground"}); selected {
		t.Fatal("ordinary sender intercepted")
	}
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	socket := strings.Index(source, "socketOwnerSetupInvocation(os.Args[1:])")
	for _, other := range []string{"actionSetupInvocation(os.Args[1:])", "actionHelperInvocation(os.Args[1:])", "journalReaderInvocation(os.Args[1:])", "flag.Parse()"} {
		if socket < 0 || socket > strings.Index(source, other) {
			t.Fatal("socket namespace not first exclusive dispatch")
		}
	}
}
func TestSocketOwnerSetupCLICapabilitiesAndPreviewInert(t *testing.T) {
	for _, mode := range []string{"capabilities", "identity", "preview"} {
		selected, o, valid := socketOwnerSetupInvocation(socketSetupCLIArgs(mode, false))
		if !selected || !valid {
			t.Fatal("fixture")
		}
		calls := 0
		var out, errs bytes.Buffer
		h := socketOwnerSetupHooks{}
		if mode != "capabilities" {
			h.identity = func(id string) bool { return id == "1234:1234" }
			h.configure = func(_ context.Context, m string, raw []byte, a lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error) {
				calls++
				if m != mode || len(raw) != 0 || a != (lanclient.SocketOwnerSetupAcknowledgements{}) {
					t.Fatal("non-offline input")
				}
				return lanclient.SocketOwnerSetupResult{SchemaVersion: lanclient.SocketOwnerSetupResultVersion, Mode: m, State: "absent"}, nil
			}
		}
		if runSocketOwnerSetup(context.Background(), o, valid, h, socketSetupPanicReader{t}, &out, &errs) != 0 {
			t.Fatal(errs.String())
		}
		if mode == "capabilities" {
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil || len(result) != 7 || result["maxPolicyBytes"] != float64(4096) || result["schemaVersion"] != "tracebolt.socket-owner-setup-capabilities.v1" || result["identityVersion"] != lanclient.SocketOwnerSetupIdentityVersion || result["resultVersion"] != lanclient.SocketOwnerSetupResultVersion || result["policyVersion"] != socketowner.PolicyVersion || result["consentVersion"] != lanclient.SocketOwnerConsentVersion || result["scope"] != socketowner.Scope || calls != 0 {
				t.Fatal("capability contract changed", out.String())
			}
		} else if calls != 1 {
			t.Fatal("wrong dispatch")
		}
	}
}
func TestSocketOwnerSetupCLIIdentityGuardBeforeStdin(t *testing.T) {
	for _, mode := range []string{"identity", "preview", "initialize", "disable"} {
		_, o, valid := socketOwnerSetupInvocation(socketSetupCLIArgs(mode, true))
		var out, errs bytes.Buffer
		h := socketOwnerSetupHooks{identity: func(string) bool { return false }, configure: func(context.Context, string, []byte, lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error) {
			t.Fatal("guard bypass")
			return lanclient.SocketOwnerSetupResult{}, nil
		}}
		if runSocketOwnerSetup(context.Background(), o, valid, h, socketSetupPanicReader{t}, &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("guard disclosed data")
		}
	}
}
func TestSocketOwnerSetupCLICanonicalPolicyAndAckCombinations(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, mode := range []string{"initialize", "disable"} {
			for bits := 0; bits < 8; bits++ {
				p := socketSetupCLIPolicy(profile, mode == "initialize")
				raw, _ := socketowner.EncodePolicy(p)
				ack := lanclient.SocketOwnerSetupAcknowledgements{Metadata: bits&1 != 0, PtraceRisk: bits&2 != 0, HTTPPlaintext: bits&4 != 0}
				expected := mode == "disable" && bits == 0 || mode == "initialize" && (profile == "tls" && bits == 3 || profile == "http-test" && bits == 7)
				calls := 0
				h := socketOwnerSetupHooks{identity: func(string) bool { return true }, configure: func(_ context.Context, m string, b []byte, a lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error) {
					calls++
					if m != mode || !bytes.Equal(raw, b) || a != ack {
						t.Fatal("changed stdin")
					}
					return lanclient.SocketOwnerSetupResult{}, nil
				}}
				var out, errs bytes.Buffer
				code := runSocketOwnerSetup(context.Background(), socketOwnerSetupOptions{mode: mode, identity: "1234:1234", ack: ack}, true, h, bytes.NewReader(raw), &out, &errs)
				if (code == 0) != expected || calls != map[bool]int{false: 0, true: 1}[expected] || !expected && out.Len() != 0 {
					t.Fatal("ack combination", profile, mode, bits, code)
				}
			}
		}
	}
	p := socketSetupCLIPolicy("tls", true)
	raw, _ := socketowner.EncodePolicy(p)
	malformed := [][]byte{nil, []byte(`{}`), []byte(`null`), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...), bytes.Repeat([]byte(" "), 4097), []byte(strings.Replace(string(raw), `"enabled":true`, `"Enabled":true`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":null`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":true,"enabled":true`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":false`, 1))}
	for _, body := range malformed {
		h := socketOwnerSetupHooks{identity: func(string) bool { return true }, configure: func(context.Context, string, []byte, lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error) {
			t.Fatal("malformed reached local state")
			return lanclient.SocketOwnerSetupResult{}, nil
		}}
		_, o, valid := socketOwnerSetupInvocation(socketSetupCLIArgs("initialize", false))
		var out, errs bytes.Buffer
		if runSocketOwnerSetup(context.Background(), o, valid, h, bytes.NewReader(body), &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("malformed accepted")
		}
	}
}

type socketSetupErrorReader struct{}

func (socketSetupErrorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE READER ERROR") }

type socketSetupShortWriter struct{}

func (socketSetupShortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestSocketOwnerSetupCLIReadWriteAndPartialFailureRedacted(t *testing.T) {
	for _, kind := range []string{"reader", "private_error", "persisted_tombstone", "output_limit", "short_output", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			mode := "disable"
			_, o, valid := socketOwnerSetupInvocation(socketSetupCLIArgs(mode, false))
			p := socketSetupCLIPolicy("tls", false)
			raw, _ := socketowner.EncodePolicy(p)
			var out, errs bytes.Buffer
			var input io.Reader = bytes.NewReader(raw)
			var output io.Writer = &out
			ctx := context.Background()
			h := socketOwnerSetupHooks{identity: func(string) bool { return true }, configure: func(context.Context, string, []byte, lanclient.SocketOwnerSetupAcknowledgements) (lanclient.SocketOwnerSetupResult, error) {
				switch kind {
				case "private_error":
					return lanclient.SocketOwnerSetupResult{}, errors.New("PRIVATE KEY OR ROW")
				case "persisted_tombstone":
					return lanclient.SocketOwnerSetupResult{}, lanclient.ErrSocketOwnerSetupDisableIncomplete
				case "output_limit":
					return lanclient.SocketOwnerSetupResult{State: strings.Repeat("x", 8193)}, nil
				}
				return lanclient.SocketOwnerSetupResult{}, nil
			}}
			if kind == "reader" {
				input = socketSetupErrorReader{}
			}
			if kind == "short_output" {
				output = socketSetupShortWriter{}
			}
			if kind == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if runSocketOwnerSetup(ctx, o, valid, h, input, output, &errs) != 2 || out.Len() != 0 || strings.Contains(errs.String(), "PRIVATE") {
				t.Fatal("failure leaked or succeeded", errs.String())
			}
			if kind == "persisted_tombstone" && !strings.Contains(errs.String(), "disabled consent was persisted; pending discard is not confirmed") {
				t.Fatal("partial state hidden")
			}
		})
	}
}

// The same synthetic actual-Go-marshaled fixture is consumed by provisioning
// tests. It pins the public projection prefix, field names and policy order.
func TestSocketOwnerSetupPublicCrossLanguageFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/socket_owner_setup_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Identity, Preview, Initialize, Disable lanclient.SocketOwnerSetupResult
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("public fixture")
	}
	identity := lanclient.ActionSetupIdentity{SchemaVersion: lanclient.SocketOwnerSetupIdentityVersion, SenderBinding: strings.Repeat("a", 64), ManagerOrigin: "https://fixture.test", EndpointID: "agent_" + strings.Repeat("b", 32), IncarnationDigest: "sha256:" + strings.Repeat("c", 64), TransportProfile: "tls", AgentUID: 1234, AgentGID: 1234}
	for _, entry := range []struct {
		mode, state string
		result      lanclient.SocketOwnerSetupResult
	}{{"identity", "absent", fixtures.Identity}, {"preview", "enabled", fixtures.Preview}, {"initialize", "enabled", fixtures.Initialize}, {"disable", "disabled", fixtures.Disable}} {
		result := entry.result
		if result.SchemaVersion != lanclient.SocketOwnerSetupResultVersion || result.Mode != entry.mode || result.State != entry.state || result.Identity != identity || result.TaggedPendingDiscarded != (entry.mode == "disable") {
			t.Fatal("fixture projection drift")
		}
		if entry.mode == "identity" {
			if result.Policy != nil {
				t.Fatal("absent policy")
			}
			continue
		}
		policy := socketSetupCLIPolicy("tls", entry.mode != "disable")
		if result.Policy == nil || *result.Policy != policy {
			t.Fatal("fixture policy drift")
		}
	}
	canonical, _ := json.Marshal(fixtures)
	if !bytes.Equal(raw, append(canonical, '\n')) {
		t.Fatal("Go canonical fixture changed")
	}
}
