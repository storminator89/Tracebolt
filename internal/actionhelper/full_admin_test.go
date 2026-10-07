package actionhelper

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"localrmm/internal/actionpermit"
)

type fullAdminFixture struct {
	properties map[string]map[string]string
	files      map[string]fullAdminFile
	commands   [][]string
	calls      map[string]int
	hook       func(string, int)
}

func fixtureV2(t *testing.T, unit string) *fullAdminFixture {
	t.Helper()
	f := &fullAdminFixture{properties: map[string]map[string]string{}, files: map[string]fullAdminFile{}, calls: map[string]int{}}
	f.add(unit)
	f.file(systemctlPath)
	return f
}
func (f *fullAdminFixture) file(name string) {
	f.files[name] = fullAdminFile{name, name, actionpermit.Digest([]byte("dynamic ELF or administrator script: " + name)), actionpermit.Digest([]byte("root identity: " + name))}
}
func (f *fullAdminFixture) add(unit string) {
	p := map[string]string{}
	for _, key := range fullAdminPropertiesForUnit(unit) {
		p[key] = ""
	}
	p["Id"], p["Names"], p["LoadState"], p["Transient"], p["NeedDaemonReload"] = unit, unit, "loaded", "no", "no"
	p["FragmentPath"] = "/usr/lib/systemd/system/" + unit
	p["ActiveState"] = "active"
	p["UnitFileState"] = "enabled"
	p["RefuseManualStart"], p["RefuseManualStop"], p["StopWhenUnneeded"] = "no", "no", "no"
	if strings.HasSuffix(unit, ".service") {
		p["User"] = "root"
		p["Group"] = "root"
		p["Type"] = "simple"
		p["ExecStart"] = "{ path=/usr/bin/ordinary-daemon ; argv[]=/usr/bin/ordinary-daemon --config /etc/daemon.conf ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
		f.file("/usr/bin/ordinary-daemon")
	}
	f.properties[unit] = p
	f.file(p["FragmentPath"])
}
func (f *fullAdminFixture) source(t *testing.T) fullAdminSource {
	t.Helper()
	return fullAdminSource{file: func(name string) (fullAdminFile, error) {
		v, ok := f.files[name]
		if !ok {
			return fullAdminFile{}, ErrRejected
		}
		return v, nil
	}, run: func(_ context.Context, args []string) ([]byte, error) {
		f.commands = append(f.commands, append([]string(nil), args...))
		if reflect.DeepEqual(args, targetListArgs()) {
			units := []string{}
			for unit := range f.properties {
				if strings.HasSuffix(unit, ".service") {
					units = append(units, unit)
				}
			}
			sort.Strings(units)
			out := ""
			for _, unit := range units {
				out += unit + " enabled enabled\n"
			}
			return []byte(out), nil
		}
		if len(args) < 3 || args[len(args)-2] != "--" {
			t.Fatal("unexpected command", args)
		}
		unit := args[len(args)-1]
		f.calls[unit]++
		if f.hook != nil {
			f.hook(unit, f.calls[unit])
		}
		p, ok := f.properties[unit]
		if !ok {
			return nil, ErrRejected
		}
		if args[len(args)-3] == "try-restart" {
			return nil, nil
		}
		keys := fullAdminPropertiesForUnit(unit)
		if reflect.DeepEqual(args, systemctlArgs("show", unit, []string{"Id", "ActiveState"})) {
			keys = []string{"Id", "ActiveState"}
		}
		out := ""
		for _, key := range keys {
			out += key + "=" + p[key] + "\n"
		}
		return []byte(out), nil
	}}
}
func TestFullAdminOrdinaryRootDynamicServicesAndDefaultDependencies(t *testing.T) {
	for _, unit := range []string{"sshd.service", "networking.service", "docker.service", "wireguard.service", "nftables.service", "database.service"} {
		t.Run(unit, func(t *testing.T) {
			f := fixtureV2(t, unit)
			f.add("sysinit.target")
			f.add("shutdown.target")
			f.properties[unit]["Requires"] = "sysinit.target"
			f.properties[unit]["Conflicts"] = "shutdown.target"
			f.properties["shutdown.target"]["ActiveState"] = "inactive"
			// Already-active prerequisite does not restart its reverse dependents.
			f.properties["sysinit.target"]["RequiredBy"] = "tracebolt-agent.service worker@instance.service " + strings.Repeat("unrelated.service ", 100)
			got, e := inspectServiceV2(context.Background(), f.source(t), unit)
			if e != nil || got.Unit != unit || got.ObservedState != Active || !actionpermit.ValidDigest(got.UnitPolicyDigest) {
				t.Fatal(got, e)
			}
			if len(got.AffectedServices) != 1 || got.AffectedServices[0] != unit {
				t.Fatal(got.AffectedServices)
			}
			for _, args := range f.commands {
				if args[len(args)-3] != "show" {
					t.Fatal("inspection mutated", args)
				}
			}
		})
	}
}
func TestFullAdminRejectsUnsupportedAuthorityAndGraph(t *testing.T) {
	cases := map[string]func(*fullAdminFixture){
		"alias":              func(f *fullAdminFixture) { f.properties["example.service"]["Names"] = "alias.service example.service" },
		"resolved_alias":     func(f *fullAdminFixture) { f.properties["example.service"]["Id"] = "other.service" },
		"template":           func(f *fullAdminFixture) { f.properties["example.service"]["Requires"] = "worker@one.service" },
		"transient":          func(f *fullAdminFixture) { f.properties["example.service"]["Transient"] = "yes" },
		"generated":          func(f *fullAdminFixture) { f.properties["example.service"]["UnitFileState"] = "generated" },
		"stale":              func(f *fullAdminFixture) { f.properties["example.service"]["NeedDaemonReload"] = "yes" },
		"untrusted_fragment": func(f *fullAdminFixture) { delete(f.files, f.properties["example.service"]["FragmentPath"]) },
		"untrusted_dropin": func(f *fullAdminFixture) {
			f.properties["example.service"]["DropInPaths"] = "/etc/systemd/system/example.service.d/change.conf"
		},
		"stop_control_plane": func(f *fullAdminFixture) { f.properties["example.service"]["ConsistsOf"] = "tracebolt-agent.service" },
		"indirect_stop_control_plane": func(f *fullAdminFixture) {
			f.add("dependent.service")
			f.properties["example.service"]["BoundBy"] = "dependent.service"
			f.properties["dependent.service"]["PropagatesStopTo"] = "localrmm.service"
		},
		"generated_fragment_alias": func(f *fullAdminFixture) {
			name := f.properties["example.service"]["FragmentPath"]
			v := f.files[name]
			v.Resolved = "/run/systemd/generator/example.service"
			f.files[name] = v
		},
		"user_fragment_alias": func(f *fullAdminFixture) {
			name := f.properties["example.service"]["FragmentPath"]
			v := f.files[name]
			v.Resolved = "/usr/lib/systemd/user/example.service"
			f.files[name] = v
		},
		"protected_exec_symlink": func(f *fullAdminFixture) {
			v := f.files["/usr/bin/ordinary-daemon"]
			v.Resolved = "/opt/tracebolt-agent/agent"
			f.files[v.Path] = v
		},
		"protected_libexec_symlink": func(f *fullAdminFixture) {
			v := f.files["/usr/bin/ordinary-daemon"]
			v.Resolved = "/usr/libexec/tracebolt-helper"
			f.files[v.Path] = v
		},
		"trigger":        func(f *fullAdminFixture) { f.properties["example.service"]["TriggeredBy"] = "example.socket" },
		"uphold":         func(f *fullAdminFixture) { f.properties["example.service"]["Upholds"] = "example-other.service" },
		"failure_job":    func(f *fullAdminFixture) { f.properties["example.service"]["OnFailure"] = "recovery.service" },
		"alternate_root": func(f *fullAdminFixture) { f.properties["example.service"]["RootDirectory"] = "/srv/root" },
		"ambiguous_exec": func(f *fullAdminFixture) {
			f.properties["example.service"]["ExecStart"] = "{ path=/usr/bin/a\\x20b ; argv[]=/usr/bin/a ; ignore_errors=no ; start_time=0 }"
		},
		"duplicate_edge": func(f *fullAdminFixture) { f.properties["example.service"]["Requires"] = "a.service a.service" },
		"oversized_graph": func(f *fullAdminFixture) {
			names := []string{}
			for i := 0; i < MaxGraphUnitsV2; i++ {
				name := fmt.Sprintf("dependency%03d.service", i)
				names = append(names, name)
				f.add(name)
			}
			f.properties["example.service"]["Wants"] = strings.Join(names, " ")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixtureV2(t, "example.service")
			change(f)
			if _, e := inspectServiceV2(context.Background(), f.source(t), "example.service"); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, unit := range []string{"tracebolt.service", "localrmm.service", "tracebolt-agent.service", "localrmm-helper.service", "worker@x.service", "x.socket", "../x.service"} {
		f := fixtureV2(t, "example.service")
		if _, e := inspectServiceV2(context.Background(), f.source(t), unit); e == nil {
			t.Fatal("protected or noncanonical target", unit)
		}
	}
}
func TestFullAdminDigestBindsConfigurationDropinsAndRelevantGraph(t *testing.T) {
	f := fixtureV2(t, "example.service")
	f.add("dependent.service")
	f.properties["example.service"]["RequiredBy"] = "dependent.service"
	before, e := inspectServiceV2(context.Background(), f.source(t), "example.service")
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before.AffectedServices, []string{"dependent.service", "example.service"}) {
		t.Fatal(before.AffectedServices)
	}
	for _, mutate := range []func(){func() { f.properties["dependent.service"]["Environment"] = "MODE=changed" }, func() {
		v := f.files[f.properties["example.service"]["FragmentPath"]]
		v.Digest = actionpermit.Digest([]byte("replacement"))
		f.files[v.Path] = v
	}, func() {
		f.properties["example.service"]["DropInPaths"] = "/etc/systemd/system/example.service.d/new.conf"
		f.file("/etc/systemd/system/example.service.d/new.conf")
	}} {
		mutate()
		after, e := inspectServiceV2(context.Background(), f.source(t), "example.service")
		if e != nil || after.UnitPolicyDigest == before.UnitPolicyDigest {
			t.Fatal("drift unbound", e)
		}
		before = after
	}
	f.hook = func(unit string, n int) {
		if unit == "example.service" && n%2 == 0 {
			f.properties[unit]["Environment"] += " DIFFERENT=1"
		}
	}
	if _, e = inspectServiceV2(context.Background(), f.source(t), "example.service"); e == nil {
		t.Fatal("mid-inspection drift accepted")
	}
}
func TestFullAdminExecRuntimeStatusDoesNotChangeDigest(t *testing.T) {
	f := fixtureV2(t, "example.service")
	before, e := inspectServiceV2(context.Background(), f.source(t), "example.service")
	if e != nil {
		t.Fatal(e)
	}
	f.properties["example.service"]["ExecStart"] = strings.ReplaceAll(f.properties["example.service"]["ExecStart"], "pid=0", "pid=42")
	after, e := inspectServiceV2(context.Background(), f.source(t), "example.service")
	if e != nil || after.UnitPolicyDigest != before.UnitPolicyDigest {
		t.Fatal("volatile exec status changed configuration", e)
	}
	b := fullAdminSystemdBackend{f.source(t)}
	impact, _ := actionpermit.AffectedServicesDigest(before.AffectedServices)
	if _, e = b.Check(context.Background(), Target{Unit: "example.service", ReviewDigest: before.UnitPolicyDigest, AffectedServicesDigest: impact}); e != nil {
		t.Fatal(e)
	}
	f.properties["example.service"]["User"] = "daemon"
	if _, e = b.Check(context.Background(), Target{Unit: "example.service", ReviewDigest: before.UnitPolicyDigest, AffectedServicesDigest: impact}); e == nil {
		t.Fatal("dispatch accepted stale digest")
	}
}
func TestFullAdminPolicyDistinctFreshScopeAndV1CanonicalBytes(t *testing.T) {
	// Pure canonical structs demonstrate no implicit promotion/default scope.
	p := Policy{Version: PolicyVersion}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "scope") {
		t.Fatal("legacy serialized shape widened")
	}
	if protectedFullAdminUnit("ssh.service") || protectedFullAdminUnit("docker.service") || !protectedUnit("ssh.service") {
		t.Fatal("legacy/new protection scopes conflated")
	}
}
