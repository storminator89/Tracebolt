//go:build linux

package agentinstall

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type unitStatus struct{ LoadState, ActiveState, FragmentPath, DropInPaths, Transient, Names, MainPID, UnitFileState string }

func actualUnitStatus(ctx context.Context) (unitStatus, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, systemctlPath, "show", UnitName, "--property=LoadState,ActiveState,FragmentPath,DropInPaths,Transient,Names,MainPID,UnitFileState", "--no-pager")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	var out cappedOutput
	cmd.Stdout = &out
	if cmd.Run() != nil || out.exceeded {
		return unitStatus{}, &preflightFailure{"preflight_unit_command", ErrPreflight}
	}
	return parseUnitStatus(out.String())
}
func parseUnitStatus(raw string) (unitStatus, error) {
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return unitStatus{}, &preflightFailure{"preflight_unit_members", ErrPreflight}
		}
		if _, ok := values[kv[0]]; ok {
			return unitStatus{}, &preflightFailure{"preflight_unit_members", ErrPreflight}
		}
		values[kv[0]] = kv[1]
	}
	required := []string{"LoadState", "ActiveState", "FragmentPath", "DropInPaths", "Transient", "Names", "MainPID", "UnitFileState"}
	if len(values) != len(required) {
		return unitStatus{}, &preflightFailure{"preflight_unit_members", ErrPreflight}
	}
	for _, k := range required {
		if _, ok := values[k]; !ok {
			return unitStatus{}, &preflightFailure{"preflight_unit_members", ErrPreflight}
		}
	}
	if _, e := strconv.ParseUint(values["MainPID"], 10, 32); e != nil {
		return unitStatus{}, &preflightFailure{"preflight_unit_pid", ErrPreflight}
	}
	return unitStatus{values["LoadState"], values["ActiveState"], values["FragmentPath"], values["DropInPaths"], values["Transient"], values["Names"], values["MainPID"], values["UnitFileState"]}, nil
}
func (s unitStatus) owned() bool {
	return (s.UnitFileState == "enabled" || s.UnitFileState == "disabled") && s.LoadState == "loaded" && s.FragmentPath == UnitPath && s.DropInPaths == "" && s.Transient == "no" && s.Names == UnitName && (s.ActiveState == "active" || s.ActiveState == "inactive" || s.ActiveState == "failed")
}
func (s unitStatus) absent() bool {
	return (s.UnitFileState == "" || s.UnitFileState == "not-found") && s.LoadState == "not-found" && s.FragmentPath == "" && s.DropInPaths == "" && s.Transient == "no" && (s.Names == "" || s.Names == UnitName) && s.MainPID == "0" && s.ActiveState == "inactive"
}
