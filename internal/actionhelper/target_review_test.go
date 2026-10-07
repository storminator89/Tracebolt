package actionhelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"localrmm/internal/actionpermit"
)

// All data below is invented in memory. No real binary, unit, host file,
// systemctl process, authority loader, socket or identity adapter is used.
func reviewELF() []byte {
	raw := make([]byte, 121)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], 2)
	binary.LittleEndian.PutUint16(raw[18:], 62)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint64(raw[24:], 0x400078)
	binary.LittleEndian.PutUint64(raw[32:], 64)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	binary.LittleEndian.PutUint16(raw[54:], 56)
	binary.LittleEndian.PutUint16(raw[56:], 1)
	binary.LittleEndian.PutUint16(raw[58:], 64)
	binary.LittleEndian.PutUint32(raw[64:], 1)
	binary.LittleEndian.PutUint32(raw[68:], 5)
	binary.LittleEndian.PutUint64(raw[80:], 0x400000)
	binary.LittleEndian.PutUint64(raw[96:], uint64(len(raw)))
	binary.LittleEndian.PutUint64(raw[104:], uint64(len(raw)))
	binary.LittleEndian.PutUint64(raw[112:], 4096)
	raw[120] = 0xc3
	return raw
}

func reviewProperties(unit string) map[string]string {
	p := map[string]string{}
	for _, key := range configurationProperties {
		p[key] = ""
	}
	p["Id"], p["Names"], p["LoadState"] = unit, unit, "loaded"
	p["FragmentPath"] = "/etc/systemd/system/" + unit
	p["Transient"], p["NeedDaemonReload"], p["Type"] = "no", "no", "simple"
	p["User"], p["Group"] = "1234", "1234"
	p["Requires"], p["After"], p["Conflicts"], p["Before"], p["WantedBy"] = "sysinit.target", "sysinit.target basic.target systemd-journald.socket", "shutdown.target", "shutdown.target", "multi-user.target"
	return p
}

func reviewPropertyBytes(p map[string]string) []byte {
	var b strings.Builder
	for _, key := range configurationProperties {
		b.WriteString(key + "=" + p[key] + "\n")
	}
	return []byte(b.String())
}

func reviewSnapshot(units ...string) SetupTargetSnapshot {
	s := SetupTargetSnapshot{Architecture: "amd64", Units: units, Properties: map[string][]byte{}, Files: map[string][]byte{}, Revisions: map[string]string{}, Unavailable: map[string]string{}}
	s.Files[systemctlPath] = []byte("invented client bytes, never executed")
	s.Files["/opt/example/daemon"] = reviewELF()
	s.Files["/etc/example/config"] = []byte("invented config, never interpreted")
	for _, unit := range units {
		p := reviewProperties(unit)
		s.Properties[unit] = reviewPropertyBytes(p)
		s.Files[p["FragmentPath"]] = []byte("[Unit]\nDescription=Fixture only\n[Service]\nType=simple\nUser=1234\nGroup=1234\nExecStart=/opt/example/daemon --config=/etc/example/config\nRestart=no\nKillMode=control-group\nTimeoutStopSec=30s\n[Install]\nWantedBy=multi-user.target\n")
	}
	for name := range s.Files {
		s.Revisions[name] = actionpermit.Digest([]byte("invented protected metadata:" + name))
	}
	return s
}

func TestSetupTargetReviewAggregatesWithoutAuthority(t *testing.T) {
	s := reviewSnapshot("worker-b.service", "worker-a.service", "sshd.service", "sample@.service")
	r, err := BuildSetupTargetReview(s)
	if err != nil || len(r.Candidates) != 2 || len(r.Unavailable) != 2 || r.Candidates[0].Unit != "worker-a.service" {
		t.Fatal(r, err)
	}
	raw, _ := json.Marshal(r)
	for _, forbidden := range []string{"reviewDigest", "unitPolicyDigest", "invented config", "--config=", "invented client"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("discovery leaked content or manufactured authority", forbidden)
		}
	}
	if len(r.Candidates[0].Inputs) != 4 || r.RequiredAssertion != SetupTargetReviewAssertion {
		t.Fatal(r)
	}
	approval := SetupTargetReviewApproval{ReportDigest: r.ReportDigest, ApprovalRecordDigest: actionpermit.Digest([]byte("fixture combined approval")), CompleteInputsAndEffectsRead: true}
	targets, err := FinalizeSetupTargetReview(r, approval)
	if err != nil || len(targets) != 2 {
		t.Fatal(targets, err)
	}
	for _, target := range targets {
		if _, err := SetupTargetDigest(target); err != nil || target.ReviewDigest != approval.ApprovalRecordDigest {
			t.Fatal("existing target validator rejected", err)
		}
	}
	targets[0].Inputs[0].Digest = "changed"
	if r.Candidates[0].Inputs[0].Digest == "changed" {
		t.Fatal("finalization shares mutable slices")
	}
	s.Units = []string{"sample@.service", "sshd.service", "worker-a.service", "worker-b.service"}
	r2, _ := BuildSetupTargetReview(s)
	if r.ReportDigest != r2.ReportDigest {
		t.Fatal("enumeration order changed exact review")
	}
}

func TestSetupTargetReviewRejectsUnsupportedSemantics(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*SetupTargetSnapshot, map[string]string)
	}{
		{"alias", "alias_or_noncanonical_loaded_identity", func(s *SetupTargetSnapshot, p map[string]string) { p["Names"] += " alias.service" }},
		{"transient", "transient_or_pending_reload", func(s *SetupTargetSnapshot, p map[string]string) { p["Transient"] = "yes" }},
		{"reload", "transient_or_pending_reload", func(s *SetupTargetSnapshot, p map[string]string) { p["NeedDaemonReload"] = "yes" }},
		{"missing", "service_not_loaded", func(s *SetupTargetSnapshot, p map[string]string) { p["LoadState"] = "not-found" }},
		{"generated", "generated_or_unsupported_fragment", func(s *SetupTargetSnapshot, p map[string]string) {
			p["FragmentPath"] = "/run/systemd/generator/sample.service"
		}},
		{"dropin", "drop_in_semantics_require_separate_review", func(s *SetupTargetSnapshot, p map[string]string) {
			p["DropInPaths"] = "/etc/systemd/system/sample.service.d/override.conf"
		}},
		{"type", "unsupported_service_type", func(s *SetupTargetSnapshot, p map[string]string) { p["Type"] = "forking" }},
		{"protected", "protected_service_relationship:After", func(s *SetupTargetSnapshot, p map[string]string) { p["After"] = "NetworkManager.service" }},
		{"related", "unsupported_service_relationship:PartOf", func(s *SetupTargetSnapshot, p map[string]string) { p["PartOf"] = "ordinary.service" }},
		{"socket", "unsupported_service_relationship:TriggeredBy", func(s *SetupTargetSnapshot, p map[string]string) { p["TriggeredBy"] = "sample.socket" }},
		{"timer", "unsupported_service_relationship:Triggers", func(s *SetupTargetSnapshot, p map[string]string) { p["Triggers"] = "sample.timer" }},
		{"root", "nonroot_numeric_identity_required", func(s *SetupTargetSnapshot, p map[string]string) { p["User"] = "0" }},
		{"missing_config", "missing_unprotected_or_oversized_input", func(s *SetupTargetSnapshot, p map[string]string) { delete(s.Files, "/etc/example/config") }},
		{"missing_revision", "missing_unprotected_or_oversized_input", func(s *SetupTargetSnapshot, p map[string]string) { delete(s.Revisions, systemctlPath) }},
		{"script", "script_or_non_elf_executable", func(s *SetupTargetSnapshot, p map[string]string) {
			s.Files["/opt/example/daemon"] = []byte("#!/bin/sh\n: hidden-argument\n")
		}},
		{"dynamic", "dynamic_executable_input_closure_unsupported", func(s *SetupTargetSnapshot, p map[string]string) {
			binary.LittleEndian.PutUint32(s.Files["/opt/example/daemon"][64:], 3)
		}},
		{"architecture", "unsupported_executable_format_or_architecture", func(s *SetupTargetSnapshot, p map[string]string) { s.Architecture = "arm64" }},
		{"unknown_error", "inspection_unavailable", func(s *SetupTargetSnapshot, p map[string]string) {
			s.Unavailable["sample.service"] = "secret subprocess error"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := reviewSnapshot("sample.service")
			p := reviewProperties("sample.service")
			tc.change(&s, p)
			s.Properties["sample.service"] = reviewPropertyBytes(p)
			r, err := BuildSetupTargetReview(s)
			if err != nil || len(r.Candidates) != 0 || len(r.Unavailable) != 1 || r.Unavailable[0].Reason != tc.reason {
				t.Fatal(r, err, tc.reason)
			}
		})
	}
}

func TestSetupTargetReviewRejectsUnitExecutionAmbiguity(t *testing.T) {
	for _, directive := range []string{"ExecStartPre=/opt/pre", "ExecStop=/opt/stop", "ExecReload=/opt/reload", "Environment=TOKEN=fixture-secret", "EnvironmentFile=/etc/env", "WorkingDirectory=/opt/example", "RootDirectory=/opt/root", "LoadCredential=key:/etc/key", "StandardOutput=file:/etc/output", "DynamicUser=yes", "Restart=always", "ExecStart=/opt/other", "Unknown=fixture-secret"} {
		t.Run(strings.Split(directive, "=")[0]+directive, func(t *testing.T) {
			s := reviewSnapshot("sample.service")
			name := "/etc/systemd/system/sample.service"
			s.Files[name] = bytes.Replace(s.Files[name], []byte("[Install]"), []byte(directive+"\n[Install]"), 1)
			r, err := BuildSetupTargetReview(s)
			if err != nil || len(r.Candidates) != 0 || len(r.Unavailable) != 1 {
				t.Fatal(r, err)
			}
			raw, _ := json.Marshal(r)
			if bytes.Contains(raw, []byte("fixture-secret")) {
				t.Fatal("raw directive leaked")
			}
		})
	}
	for _, command := range []string{"/opt/example/daemon $TOKEN", "/opt/example/daemon %i", "/opt/example/daemon ./relative", "/opt/example/daemon --config=/var/lib/config", "/opt/example/daemon 'quoted'", "-/opt/example/daemon", "/opt/example/daemon a;true", "/opt/example/daemon --config=relative/file"} {
		s := reviewSnapshot("sample.service")
		name := "/etc/systemd/system/sample.service"
		s.Files[name] = bytes.Replace(s.Files[name], []byte("/opt/example/daemon --config=/etc/example/config"), []byte(command), 1)
		r, err := BuildSetupTargetReview(s)
		if err != nil || len(r.Candidates) != 0 {
			t.Fatal(command, r, err)
		}
	}
}

func TestSetupTargetReviewFinalizationRequiresExactExplicitAssertion(t *testing.T) {
	for _, kind := range []string{"no_assertion", "wrong_review", "no_approval", "mutated_candidate", "mutated_exclusion", "json_import", "empty"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := BuildSetupTargetReview(reviewSnapshot("sample.service", "ssh.service"))
			a := SetupTargetReviewApproval{r.ReportDigest, actionpermit.Digest([]byte("fixture approval")), true}
			switch kind {
			case "no_assertion":
				a.CompleteInputsAndEffectsRead = false
			case "wrong_review":
				a.ReportDigest = actionpermit.Digest(nil)
			case "no_approval":
				a.ApprovalRecordDigest = ""
			case "mutated_candidate":
				r.Candidates[0].Inputs[0].Digest = actionpermit.Digest(nil)
			case "mutated_exclusion":
				r.Unavailable[0].Reason = "silently omitted"
			case "json_import":
				raw, _ := json.Marshal(r)
				r = SetupTargetReview{}
				_ = json.Unmarshal(raw, &r)
			case "empty":
				r, _ = BuildSetupTargetReview(reviewSnapshot("ssh.service"))
				a.ReportDigest = r.ReportDigest
			}
			if _, err := FinalizeSetupTargetReview(r, a); err == nil {
				t.Fatal("finalized without matching approved review")
			}
		})
	}
}

func TestSetupTargetReviewPinsConfigurationBytesAndObjectRevision(t *testing.T) {
	base := reviewSnapshot("sample.service")
	r, _ := BuildSetupTargetReview(base)
	for _, kind := range []string{"config", "file", "revision"} {
		s := reviewSnapshot("sample.service")
		switch kind {
		case "config":
			p := reviewProperties("sample.service")
			p["Before"] = "shutdown.target multi-user.target"
			s.Properties["sample.service"] = reviewPropertyBytes(p)
		case "file":
			s.Files["/etc/example/config"] = []byte("changed")
		case "revision":
			s.Revisions["/etc/example/config"] = actionpermit.Digest([]byte("replacement inode"))
		}
		changed, err := BuildSetupTargetReview(s)
		if err != nil || changed.ReportDigest == r.ReportDigest {
			t.Fatal(kind, err)
		}
	}
}

func TestSetupTargetReviewAggregateLimitDoesNotSelectArbitrarySubset(t *testing.T) {
	units := []string{}
	for n := 0; n < 17; n++ {
		units = append(units, fmt.Sprintf("fixture-%02d.service", n))
	}
	r, err := BuildSetupTargetReview(reviewSnapshot(units...))
	if err != nil || len(r.Candidates) != 0 || len(r.Unavailable) != 17 {
		t.Fatal(r, err)
	}
	for _, u := range r.Unavailable {
		if u.Reason != "aggregate_target_limit_exceeded" {
			t.Fatal(u)
		}
	}
	for _, bad := range [][]string{{"duplicate.service", "duplicate.service"}, {"bad\nname.service"}, {"/tmp/x.service"}} {
		if _, err := BuildSetupTargetReview(reviewSnapshot(bad...)); err == nil {
			t.Fatal(bad)
		}
	}
}

func reviewSource(s SetupTargetSnapshot, commands *[][]string) setupReviewSource {
	return setupReviewSource{identity: func() error { return nil }, read: func(name string) (setupReviewFile, error) {
		raw, ok := s.Files[name]
		if !ok {
			return setupReviewFile{}, errors.New("inert file unavailable")
		}
		return setupReviewFile{bytes.Clone(raw), s.Revisions[name]}, nil
	}, run: func(_ context.Context, args []string) ([]byte, error) {
		*commands = append(*commands, slices.Clone(args))
		if reflect.DeepEqual(args, targetListArgs()) {
			var b strings.Builder
			for _, unit := range s.Units {
				b.WriteString(unit + " enabled enabled\n")
			}
			return []byte(b.String()), nil
		}
		for _, unit := range s.Units {
			if reflect.DeepEqual(args, systemctlArgs("show", unit, configurationProperties)) {
				return bytes.Clone(s.Properties[unit]), nil
			}
		}
		return nil, errors.New("non-read-only command refused by fixture")
	}}
}

func TestSetupTargetReviewInspectionUsesOnlyInjectedReadOperations(t *testing.T) {
	s := reviewSnapshot("sample.service", "ssh.service", "worker@.service")
	commands := [][]string{}
	source := reviewSource(s, &commands)
	r, err := inspectSetupTargetReview(context.Background(), source, "amd64")
	if err != nil || len(r.Candidates) != 1 || len(commands) != 4 {
		t.Fatal(r, err, commands)
	}
	for _, args := range commands {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "restart") || strings.Contains(joined, "ssh.service") || strings.Contains(joined, "worker@") {
			t.Fatal(args)
		}
	}
	if _, err := inspectSetupTargetReview(nil, source, "amd64"); err == nil {
		t.Fatal("nil context")
	}
}

func TestSetupTargetReviewInspectionRejectsDriftAndProtectionFailure(t *testing.T) {
	for _, kind := range []string{"binary_missing", "identity", "list_drift", "properties_drift", "file_drift", "inode_drift", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			s := reviewSnapshot("sample.service")
			commands := [][]string{}
			source := reviewSource(s, &commands)
			originalRun, originalRead := source.run, source.read
			listCount, showCount := 0, 0
			reads := map[string]int{}
			source.run = func(ctx context.Context, args []string) ([]byte, error) {
				raw, err := originalRun(ctx, args)
				if reflect.DeepEqual(args, targetListArgs()) {
					listCount++
					if kind == "list_drift" && listCount == 2 {
						raw = append(raw, []byte("new.service disabled enabled\n")...)
					}
				} else {
					showCount++
					if kind == "properties_drift" && showCount == 2 {
						raw = bytes.Replace(raw, []byte("Group=1234"), []byte("Group=1235"), 1)
					}
				}
				return raw, err
			}
			source.read = func(name string) (setupReviewFile, error) {
				reads[name]++
				f, err := originalRead(name)
				if kind == "binary_missing" && name == systemctlPath {
					return setupReviewFile{}, ErrRejected
				}
				if reads[name] == 2 && name == "/etc/example/config" {
					if kind == "file_drift" {
						f.raw = []byte("changed")
					}
					if kind == "inode_drift" {
						f.revision = actionpermit.Digest(nil)
					}
				}
				return f, err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			if kind == "identity" {
				source.identity = func() error { return ErrRejected }
			}
			if _, err := inspectSetupTargetReview(ctx, source, "amd64"); err == nil {
				t.Fatal("accepted drift", kind)
			}
			if (kind == "identity" || kind == "binary_missing" || kind == "cancel") && len(commands) != 0 {
				t.Fatal("commands before admission")
			}
		})
	}
}

func TestSetupTargetReviewStrictListingAndPropertyParsing(t *testing.T) {
	for _, raw := range []string{"x.service disabled enabled trailing\n", "x.service\n", "x.service disabled\nx.service disabled\n", "x.service disabled\r\n", "x.service disabled\n\n", "x.service disabled\x00"} {
		if _, err := parseListedServices([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	for _, suffix := range []string{"Id=sample.service\n", "Unknown=secret\n"} {
		s := reviewSnapshot("sample.service")
		s.Properties["sample.service"] = append(s.Properties["sample.service"], []byte(suffix)...)
		r, err := BuildSetupTargetReview(s)
		if err != nil || len(r.Candidates) != 0 || r.Unavailable[0].Reason != "incomplete_or_invalid_loaded_properties" {
			t.Fatal(r, err)
		}
	}
}

func TestSetupTargetReviewFinalizedTargetKeepsExistingRuntimeChecks(t *testing.T) {
	s := reviewSnapshot("sample.service")
	r, err := BuildSetupTargetReview(s)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := FinalizeSetupTargetReview(r, SetupTargetReviewApproval{r.ReportDigest, actionpermit.Digest([]byte("fixture approval")), true})
	if err != nil {
		t.Fatal(err)
	}
	backend := &systemdBackend{input: func(pin FilePin) error {
		if actionpermit.Digest(s.Files[pin.Path]) != pin.Digest {
			return ErrRejected
		}
		return nil
	}, run: func(_ context.Context, args []string) ([]byte, error) {
		if reflect.DeepEqual(args, systemctlArgs("show", "sample.service", configurationProperties)) {
			return s.Properties["sample.service"], nil
		}
		if reflect.DeepEqual(args, systemctlArgs("show", "sample.service", []string{"Id", "ActiveState"})) {
			return []byte("Id=sample.service\nActiveState=active\n"), nil
		}
		t.Fatal("fixture refused unexpected command", args)
		return nil, ErrRejected
	}}
	if observed, err := backend.Check(context.Background(), targets[0]); err != nil || observed != Active {
		t.Fatal(observed, err)
	}
	s.Files["/etc/example/config"] = []byte("changed after combined install approval")
	if _, err := backend.Check(context.Background(), targets[0]); err == nil {
		t.Fatal("changed input passed existing runtime check")
	}
	for _, name := range []string{"/usr/bin/bash", "/opt/busybox", "/usr/bin/python3.12", "/usr/bin/env"} {
		if !knownInterpreterOrWrapper(name) {
			t.Fatal(name)
		}
	}
}
