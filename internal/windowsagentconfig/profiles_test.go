package windowsagentconfig

import (
	"reflect"
	"testing"
)

func TestWindowsStoreSchemasRemainSeparateAndFixed(t *testing.T) {
	const sid = "S-1-5-80-1-2-3-4-5"
	enrollment, sender, root, installer := Enrollment(sid, false), Sender(sid, false), RuntimeRoot(sid, false), Installer(false)
	if enrollment.RuntimeSID != sid || sender.RuntimeSID != sid || root.RuntimeSID != sid || !installer.InstallerOnly || installer.RuntimeSID != "" {
		t.Fatal("store identity scopes mixed")
	}
	if !reflect.DeepEqual(sender.Names, []string{"state.json"}) || !reflect.DeepEqual(enrollment.Directories, []string{"telemetry"}) || !reflect.DeepEqual(root.Directories, []string{"enrollment"}) {
		t.Fatal("unexpected state schema")
	}
	if sender.MaxBytes != 128<<10 || enrollment.MaxBytes != 1<<20 || root.MaxBytes != 64<<10 || installer.MaxBytes != 64<<10 {
		t.Fatal("state bounds expanded")
	}
	if Enrollment(sid, true).Create != true || Sender(sid, true).Create != true || RuntimeRoot(sid, true).Create != true || Installer(true).Create != true {
		t.Fatal("create must be explicit")
	}
	names := map[string]bool{}
	for _, s := range []string{enrollment.LockName, enrollment.TempName, sender.LockName, sender.TempName, root.LockName, root.TempName, installer.LockName, installer.TempName} {
		if names[s] {
			t.Fatal("store metadata names collide")
		}
		names[s] = true
	}
}
