package actionhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/actionpermit"
	"os/exec"
	"strings"
	"time"
)

const systemctlPath = "/usr/bin/systemctl"
const maxShowBytes = 64 << 10

// Backend is trusted local code, never selected or described by IPC. Tests
// inject inert implementations; Run constructs only the fixed systemctl adapter.
type Backend interface {
	Check(context.Context, Target) (Observation, error)
	TryRestart(context.Context, string) error
	Observe(context.Context, string) (Observation, error)
}
type Observation string

const (
	Active   Observation = "active"
	Inactive Observation = "inactive"
	Failed   Observation = "failed"
	Unknown  Observation = "unknown"
)

// These are stable configuration/relationship properties, not volatile Exec
// status fields. The local review pins their exact canonical fingerprint, and
// the unit files/inputs. This list does not infer or prove dependency safety.
var configurationProperties = []string{
	"Id", "Names", "LoadState", "FragmentPath", "DropInPaths", "Transient", "NeedDaemonReload",
	"Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Conflicts", "Before", "After",
	"RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "ConsistsOf", "ConflictedBy",
	"PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo", "StopPropagatedFrom",
	"OnFailure", "OnSuccess", "Triggers", "TriggeredBy", "Upholds", "UpheldBy", "Type", "User", "Group",
}

type commandRunner func(context.Context, []string) ([]byte, error)
type systemdBackend struct {
	run   commandRunner
	input func(FilePin) error
}

func newSystemdBackend() Backend { return &systemdBackend{run: runSystemctl, input: checkPinnedInput} }
func systemctlArgs(verb string, unit string, properties []string) []string {
	args := []string{"--system", "--no-ask-password", "--no-pager"}
	if verb == "show" {
		args = append(args, "--all", "--property="+strings.Join(properties, ","))
	} else {
		args = append(args, "--job-mode=fail")
	}
	return append(args, verb, "--", unit)
}

// runSystemctl is never called by automated tests. No shell, PATH lookup,
// inherited DBUS/SYSTEMD/LD variables, caller arguments or output logging.
// Killing the client on timeout DOES NOT cancel an already queued systemd job;
// the caller consequently records needs_intervention for every error.
func runSystemctl(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, systemctlPath, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	out := &boundedOutput{limit: maxShowBytes}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err != nil || out.overflow {
		return nil, ErrUnavailable
	}
	return bytes.Clone(out.Bytes()), nil
}

type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
func parseProperties(raw []byte, keys []string) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > maxShowBytes || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrRejected
	}
	m := make(map[string]string, len(keys))
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !allowed[k] || strings.ContainsRune(v, '\r') {
			return nil, ErrRejected
		}
		if _, exists := m[k]; exists {
			return nil, ErrRejected
		}
		m[k] = v
	}
	if len(m) != len(keys) {
		return nil, ErrRejected
	}
	return m, nil
}
func configurationDigest(m map[string]string) string {
	values := make([]string, 0, len(configurationProperties))
	for _, k := range configurationProperties {
		values = append(values, m[k])
	}
	raw, _ := json.Marshal(values)
	return digestBytes(raw)
}
func digestBytes(raw []byte) string { return actionpermit.Digest(raw) }
func (b *systemdBackend) Check(ctx context.Context, t Target) (Observation, error) {
	if _, e := targetDigest(t); e != nil {
		return Unknown, e
	}
	// The fixed client binary is itself part of the locally reviewed input pins.
	pinned := map[string]bool{}
	for _, f := range t.Inputs {
		if e := b.input(f); e != nil {
			return Unknown, e
		}
		pinned[f.Path] = true
	}
	if !pinned[systemctlPath] {
		return Unknown, ErrRejected
	}
	for _, u := range t.Units {
		if ctx.Err() != nil {
			return Unknown, ctx.Err()
		}
		raw, e := b.run(ctx, systemctlArgs("show", u.Unit, configurationProperties))
		if e != nil {
			return Unknown, e
		}
		p, e := parseProperties(raw, configurationProperties)
		if e != nil {
			return Unknown, e
		}
		// Sole Names is an initial conservative support limit, not a general systemd
		// safety requirement. Aliases, transient/generated units and stale reloads
		// are intentionally unsupported.
		if p["Id"] != u.Unit || p["Names"] != u.Unit || p["LoadState"] != "loaded" || p["Transient"] != "no" || p["NeedDaemonReload"] != "no" || !pinned[p["FragmentPath"]] || !safeInputPath(p["FragmentPath"]) {
			return Unknown, ErrRejected
		}
		for _, f := range strings.Fields(p["DropInPaths"]) {
			if !pinned[f] || !safeInputPath(f) {
				return Unknown, ErrRejected
			}
		}
		if configurationDigest(p) != u.ConfigurationDigest {
			return Unknown, ErrRejected
		}
	}
	return b.Observe(ctx, t.Unit)
}
func (b *systemdBackend) TryRestart(ctx context.Context, unit string) error {
	if !canonicalUnit(unit) || protectedUnit(unit) {
		return ErrRejected
	}
	_, e := b.run(ctx, systemctlArgs("try-restart", unit, nil))
	return e
}
func (b *systemdBackend) Observe(ctx context.Context, unit string) (Observation, error) {
	if !canonicalUnit(unit) || protectedUnit(unit) {
		return Unknown, ErrRejected
	}
	raw, e := b.run(ctx, systemctlArgs("show", unit, []string{"Id", "ActiveState"}))
	if e != nil {
		return Unknown, e
	}
	p, e := parseProperties(raw, []string{"Id", "ActiveState"})
	if e != nil || p["Id"] != unit {
		return Unknown, ErrRejected
	}
	switch p["ActiveState"] {
	case "active":
		return Active, nil
	case "inactive":
		return Inactive, nil
	case "failed":
		return Failed, nil
	default:
		return Unknown, nil
	}
}
