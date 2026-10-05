//go:build linux

package actionhelper

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/actionpermit"
)

func fixtureProperties() map[string]string {
	m := map[string]string{}
	for _, k := range configurationProperties {
		m[k] = ""
	}
	m["Id"] = "fixture.service"
	m["Names"] = "fixture.service"
	m["LoadState"] = "loaded"
	m["FragmentPath"] = "/usr/lib/systemd/system/fixture.service"
	m["Transient"] = "no"
	m["NeedDaemonReload"] = "no"
	m["Type"] = "simple"
	return m
}
func propertiesOutput(m map[string]string, keys []string) []byte {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + "\n")
	}
	return []byte(b.String())
}
func TestFixedBackendChecksPinsAndExactTryRestart(t *testing.T) {
	a, _ := fixtureAuthority()
	target := a.Policy.Targets[0]
	props := fixtureProperties()
	target.Units[0].ConfigurationDigest = configurationDigest(props)
	var commands [][]string
	var files []FilePin
	b := &systemdBackend{input: func(f FilePin) error { files = append(files, f); return nil }, run: func(_ context.Context, args []string) ([]byte, error) {
		commands = append(commands, append([]string(nil), args...))
		if reflect.DeepEqual(args, systemctlArgs("show", target.Unit, configurationProperties)) {
			return propertiesOutput(props, configurationProperties), nil
		}
		if reflect.DeepEqual(args, systemctlArgs("show", target.Unit, []string{"Id", "ActiveState"})) {
			return []byte("Id=fixture.service\nActiveState=active\n"), nil
		}
		if reflect.DeepEqual(args, []string{"--system", "--no-ask-password", "--no-pager", "--job-mode=fail", "try-restart", "--", "fixture.service"}) {
			return nil, nil
		}
		t.Fatalf("unexpected command %q", args)
		return nil, nil
	}}
	observed, e := b.Check(context.Background(), target)
	if e != nil || observed != Active {
		t.Fatal(observed, e)
	}
	if len(files) != len(target.Inputs) || len(commands) != 2 {
		t.Fatal(files, commands)
	}
	if e = b.TryRestart(context.Background(), target.Unit); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(commands[0], " "), "--all --property=") {
		t.Fatal("empty property support missing", commands[0])
	}
}
func TestBackendMismatchNeverInvokesTryRestart(t *testing.T) {
	for _, kind := range []string{"alias", "names", "transient", "reload", "missing_fragment", "dropin", "config_changed", "dependency_changed", "input_changed", "missing_systemctl", "truncated", "duplicate", "unknown_field", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := fixtureAuthority()
			target := a.Policy.Targets[0]
			props := fixtureProperties()
			target.Units[0].ConfigurationDigest = configurationDigest(props)
			switch kind {
			case "alias":
				props["Id"] = "real.service"
			case "names":
				props["Names"] = "fixture.service alias.service"
			case "transient":
				props["Transient"] = "yes"
			case "reload":
				props["NeedDaemonReload"] = "yes"
			case "missing_fragment":
				props["FragmentPath"] = "/etc/systemd/system/unpinned.service"
			case "dropin":
				props["DropInPaths"] = "/etc/systemd/system/fixture.service.d/override.conf"
			case "config_changed":
				props["Type"] = "forking"
			case "dependency_changed":
				props["PartOf"] = "sshd.service"
			case "missing_systemctl":
				target.Inputs = target.Inputs[1:]
			}
			calls := 0
			b := &systemdBackend{input: func(FilePin) error {
				if kind == "input_changed" {
					return ErrRejected
				}
				return nil
			}, run: func(_ context.Context, args []string) ([]byte, error) {
				calls++
				if strings.Contains(strings.Join(args, " "), "try-restart") {
					t.Fatal("unexpected action")
				}
				raw := propertiesOutput(props, configurationProperties)
				switch kind {
				case "truncated":
					return raw[:len(raw)-1-6], nil
				case "duplicate":
					return append(raw, []byte("Id=fixture.service\n")...), nil
				case "unknown_field":
					return append(raw, []byte("Arbitrary=value\n")...), nil
				case "oversized":
					return []byte(strings.Repeat("x", maxShowBytes+1)), nil
				}
				return raw, nil
			}}
			if _, e := b.Check(context.Background(), target); e == nil {
				t.Fatal("accepted", kind)
			}
			if (kind == "input_changed" || kind == "missing_systemctl") && calls != 0 {
				t.Fatal("inspected before fixed binary/input validation")
			}
		})
	}
}
func TestBackendRejectsDangerousUnitArguments(t *testing.T) {
	calls := 0
	b := &systemdBackend{run: func(context.Context, []string) ([]byte, error) { calls++; return nil, nil }}
	for _, unit := range []string{"--help", "/tmp/x.service", "foo@bar.service", "foo*.service", "foo.service\nbar.service", "tracebolt-agent.service", "sshd.service", "NetworkManager.service", "nftables.service", "systemd-networkd.service", "dbus.service"} {
		if e := b.TryRestart(context.Background(), unit); e == nil {
			t.Fatal(unit)
		}
	}
	if calls != 0 {
		t.Fatal(calls)
	}
}
func TestBackendObservationAndClientFailure(t *testing.T) {
	for _, state := range []string{"active", "inactive", "failed", "activating", "deactivating", "unknown"} {
		t.Run(state, func(t *testing.T) {
			b := &systemdBackend{run: func(context.Context, []string) ([]byte, error) {
				return []byte("Id=fixture.service\nActiveState=" + state + "\n"), nil
			}}
			o, e := b.Observe(context.Background(), "fixture.service")
			if e != nil {
				t.Fatal(e)
			}
			want := Unknown
			if state == "active" {
				want = Active
			}
			if state == "inactive" {
				want = Inactive
			}
			if state == "failed" {
				want = Failed
			}
			if o != want {
				t.Fatal(o, want)
			}
		})
	}
	b := &systemdBackend{run: func(context.Context, []string) ([]byte, error) { return nil, context.DeadlineExceeded }}
	if !errors.Is(b.TryRestart(context.Background(), "fixture.service"), context.DeadlineExceeded) {
		t.Fatal("lost uncertainty")
	}
}
func TestConfigurationFingerprintStableOrderAndExplicitEmptyValues(t *testing.T) {
	p := fixtureProperties()
	raw := propertiesOutput(p, configurationProperties)
	parsed, e := parseProperties(raw, configurationProperties)
	if e != nil {
		t.Fatal(e)
	}
	if configurationDigest(parsed) != configurationDigest(p) {
		t.Fatal("changed")
	}
	p["PartOf"] = "another.service"
	if configurationDigest(parsed) == configurationDigest(p) {
		t.Fatal("dependency unbound")
	}
	if !actionpermit.ValidDigest(configurationDigest(parsed)) {
		t.Fatal("bad digest")
	}
}
func TestBoundedOutputDoesNotRetainExcess(t *testing.T) {
	b := &boundedOutput{limit: 4}
	if n, e := b.Write([]byte("four")); e != nil || n != 4 {
		t.Fatal(n, e)
	}
	if _, e := b.Write([]byte("secret over limit")); e == nil || !b.overflow || b.String() != "four" {
		t.Fatal(e, b.String())
	}
}
