package macosservice

import (
	"strings"
)

// launchctl's human-readable output is not a stable API. These parsers accept
// only the narrow forms reviewed in source fixtures. Any format drift or
// uncertainty blocks mutation and must be investigated on a disposable Mac.
func parseDisabledSystem(raw string) (Presence, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !strings.HasSuffix(raw, "\n") || strings.ContainsRune(raw, 0) {
		return "", ErrPreflight
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) < 2 || lines[0] != "disabled services = {" || lines[len(lines)-1] != "}" {
		return "", ErrPreflight
	}
	seen := map[string]bool{}
	result := Absent
	for _, line := range lines[1 : len(lines)-1] {
		if !strings.HasPrefix(line, "\t\"") {
			return "", ErrPreflight
		}
		name, value, ok := strings.Cut(strings.TrimPrefix(line, "\t\""), "\" => ")
		if !ok || name == "" || len(name) > 512 || strings.ContainsAny(name, "\"\\\t\r\n") || seen[name] {
			return "", ErrPreflight
		}
		seen[name] = true
		if value != "true" && value != "false" && value != "enabled" && value != "disabled" {
			return "", ErrPreflight
		}
		if name == Label {
			result = Present
		}
	}
	return result, nil
}

func parseMissingService(stdout, stderr string, exit int) bool {
	return exit != 0 && stdout == "" && (stderr == "Could not find service \""+Label+"\" in domain for system\n" || stderr == "Could not find service \""+Label+"\" in domain for system\r\n")
}

func expectedLaunchArguments(o Ownership) []string {
	interval := "30s"
	if o.CollectionProfile == InventoryProfile {
		interval = "1m0s"
	}
	return []string{AgentPath, "--config", ConfigPath, "--foreground", "--interval", interval, "--service-identity", o.ServiceIdentity}
}

// parseOwnedJob checks the observed system-domain registration against the
// protected exact plist. It does not claim process health or independently prove
// that launchd honored its UserName/GroupName runtime credential settings.
func parseOwnedJob(raw string, o Ownership) bool {
	if !o.valid() || len(raw) == 0 || len(raw) > 1<<20 || !strings.HasSuffix(raw, "\n") || strings.ContainsRune(raw, 0) {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "system/"+Label+" = {" {
		return false
	}
	fields := map[string]string{}
	var args []string
	depth := 1
	inArgs := false
	argsDone := false
	for index, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if inArgs {
			if line == "}" {
				inArgs, argsDone = false, true
				depth--
				if depth != 1 {
					return false
				}
				continue
			}
			if line == "" || len(line) > 4096 || strings.ContainsAny(line, "{}") {
				return false
			}
			args = append(args, line)
			continue
		}
		if line == "}" {
			depth--
			if depth < 0 || depth == 0 && index != len(lines)-2 {
				return false
			}
			continue
		}
		if depth == 0 || line == "" {
			return false
		}
		if line == "arguments = {" {
			if argsDone || depth != 1 {
				return false
			}
			inArgs = true
			depth++
			continue
		}
		if strings.HasSuffix(line, " = {") {
			depth++
			if depth > 8 {
				return false
			}
			continue
		}
		if strings.HasPrefix(line, "arguments =") || strings.ContainsAny(line, "{}") {
			return false
		}
		for _, key := range []string{"path", "type", "program"} {
			if strings.HasPrefix(line, key+" = ") {
				if depth != 1 {
					return false
				}
				if _, exists := fields[key]; exists {
					return false
				}
				fields[key] = strings.TrimPrefix(line, key+" = ")
			}
		}
	}
	if inArgs || depth != 0 || !argsDone || fields["path"] != PlistPath || fields["type"] != "LaunchDaemon" || fields["program"] != AgentPath {
		return false
	}
	want := expectedLaunchArguments(o)
	if len(args) != len(want) {
		return false
	}
	for i := range want {
		if args[i] != want[i] {
			return false
		}
	}
	return true
}
