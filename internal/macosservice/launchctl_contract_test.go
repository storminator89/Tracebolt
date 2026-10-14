package macosservice

import (
	"strings"
	"testing"
)

func TestDisabledSystemRequiresPositiveCompleteObservation(t *testing.T) {
	for _, raw := range []string{"", "permission denied", "disabled services = {\n", "other = {\n}\n", "header\ndisabled services = {\n}\n", "disabled services = {\n}\nextra = {\n}\n", "disabled services = {\n\t\"other\" => maybe\n}\n", "disabled services = {\n\t\"other\" => false\n\t\"other\" => true\n}\n", "disabled services = {\n\t\"other\" => false\n"} {
		if _, err := parseDisabledSystem(raw); err == nil {
			t.Fatalf("accepted uncertain output %q", raw)
		}
	}
	for _, row := range []string{"", "\t\"com.tracebolt.agent\" => true\n", "\t\"com.tracebolt.agent\" => disabled\n", "\t\"com.tracebolt.agent\" => false\n"} {
		got, err := parseDisabledSystem("disabled services = {\n" + row + "}\n")
		want := Absent
		if row != "" {
			want = Present
		}
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", row, got, err)
		}
	}
}

func TestMissingJobRequiresKnownExactFailure(t *testing.T) {
	good := "Could not find service \"" + Label + "\" in domain for system\n"
	if !parseMissingService("", good, 113) {
		t.Fatal("known absence rejected")
	}
	for _, test := range []struct {
		out, err string
		code     int
	}{
		{"", good, 0}, {"", "permission denied\n", 113}, {"", "Could not find service \"other\" in domain for system\n", 113}, {"unknown", good, 113},
	} {
		if parseMissingService(test.out, test.err, test.code) {
			t.Fatalf("uncertain job falsely absent: %+v", test)
		}
	}
}

func TestJobBindingRequiresExactPathTypeProgramArguments(t *testing.T) {
	r := fixtureRequest()
	p, err := Plan(r)
	if err != nil {
		t.Fatal(err)
	}
	o := Ownership{"tracebolt.macos-service-owner.v1", Label, r.ServiceIdentity, BasicProfile, AgentPath, r.AgentSHA256, r.SourceArchive, r.SourceSHA256, ConfigPath, strings.Repeat("b", 64), strings.Repeat("c", 64), PlistPath, p.PlistSHA256}
	line := func(s string) string { return "\t" + s + "\n" }
	raw := "system/" + Label + " = {\n" + line("path = "+PlistPath) + line("type = LaunchDaemon") + line("program = "+AgentPath) + line("arguments = {")
	for _, arg := range expectedLaunchArguments(o) {
		raw += line(arg)
	}
	raw += line("}") + "}\n"
	if !parseOwnedJob(raw, o) {
		t.Fatal("exact job rejected")
	}
	for _, bad := range []string{
		strings.TrimSuffix(raw, "}\n"),
		raw + "extra = {\n}\n",
		strings.Replace(raw, "program = "+AgentPath, "program = "+AgentPath+"\n\tother = {\n\tprogram = "+AgentPath+"\n\t}", 1),
		strings.Replace(raw, PlistPath, "/Library/LaunchDaemons/foreign.plist", 1),
		strings.Replace(raw, "type = LaunchDaemon", "type = LaunchAgent", 1),
		strings.Replace(raw, "program = "+AgentPath, "program = /bin/sh", 1),
		strings.Replace(raw, "--foreground", "--validate-guided", 1),
		strings.Replace(raw, "\t--foreground\n", "", 1),
		strings.Replace(raw, "program = "+AgentPath, "program = "+AgentPath+"\n\tprogram = "+AgentPath, 1),
		strings.Replace(raw, "system/"+Label, "gui/501/"+Label, 1),
	} {
		if parseOwnedJob(bad, o) {
			t.Fatalf("accepted drifted job %q", bad)
		}
	}
}
