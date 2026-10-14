package macosservice

import "testing"

func TestHeldInstallerAllowsOnlyDirectoryTimestampAdvance(t *testing.T) {
	original := heldInstallIdentity{Device: 1, Inode: 2, UID: 0, GID: 0, Mode: 0755, Links: 3, Flags: 4, Size: 4096, MtimeSeconds: 10, CtimeSeconds: 10}
	afterOwnedChild := original
	afterOwnedChild.Links++
	afterOwnedChild.Size++
	afterOwnedChild.MtimeSeconds++
	afterOwnedChild.CtimeSeconds++
	if !sameHeldInstallIdentity(original, afterOwnedChild, false) {
		t.Fatal("owned custody child invalidated held installer ancestor")
	}
	if sameHeldInstallIdentity(original, afterOwnedChild, true) {
		t.Fatal("changed installer executable accepted")
	}
	entryChangedDuringRead := afterOwnedChild
	entryChangedDuringRead.Links++
	entryChangedDuringRead.CtimeNanoseconds++
	if sameHeldInstallIdentity(afterOwnedChild, entryChangedDuringRead, true) {
		t.Fatal("current held directory and path entry disagreed")
	}
	for _, drift := range []func(*heldInstallIdentity){func(v *heldInstallIdentity) { v.Device++ }, func(v *heldInstallIdentity) { v.Inode++ }, func(v *heldInstallIdentity) { v.UID++ }, func(v *heldInstallIdentity) { v.GID++ }, func(v *heldInstallIdentity) { v.Mode++ }, func(v *heldInstallIdentity) { v.Flags++ }, func(v *heldInstallIdentity) { v.Links = 0 }} {
		v := original
		drift(&v)
		if sameHeldInstallIdentity(original, v, false) || sameHeldInstallIdentity(original, v, true) {
			t.Fatal("changed path identity accepted")
		}
	}
	changedLinks := original
	changedLinks.Links++
	if !sameHeldInstallIdentity(original, changedLinks, false) || sameHeldInstallIdentity(original, changedLinks, true) {
		t.Fatal("directory link count policy drift")
	}
}

func TestRegisteredPrivateDirectoryAllowsSenderUpdatesButRejectsDrift(t *testing.T) {
	original := heldInstallIdentity{Device: 4, Inode: 8, UID: 501, GID: 501, Mode: 040700, Links: 2, Flags: 0, Size: 128, MtimeSeconds: 10, CtimeSeconds: 10}
	current := original
	current.Links++
	current.Size += 64
	current.MtimeSeconds++
	current.CtimeNanoseconds++
	if !samePhaseDirectoryNode(original, current, current, true) {
		t.Fatal("rejected healthy sender directory metadata change")
	}
	if samePhaseDirectoryNode(original, current, current, false) {
		t.Fatal("pre-bootstrap gate accepted sender directory metadata change")
	}
	for name, drift := range map[string]func(*heldInstallIdentity){
		"device": func(v *heldInstallIdentity) { v.Device++ },
		"inode":  func(v *heldInstallIdentity) { v.Inode++ },
		"owner":  func(v *heldInstallIdentity) { v.UID++ },
		"group":  func(v *heldInstallIdentity) { v.GID++ },
		"mode":   func(v *heldInstallIdentity) { v.Mode++ },
		"flags":  func(v *heldInstallIdentity) { v.Flags++ },
		"links":  func(v *heldInstallIdentity) { v.Links = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			drifted := current
			drift(&drifted)
			if samePhaseDirectoryNode(original, drifted, drifted, true) {
				t.Fatal("accepted changed private directory identity or policy")
			}
		})
	}
	entry := current
	entry.MtimeNanoseconds++
	if samePhaseDirectoryNode(original, current, entry, true) {
		t.Fatal("accepted unstable current pathname entry")
	}
	// Native darwinprotect.Fstat additionally rejects an expanding ACL before
	// these stat-identity comparisons; only a disposable Mac can exercise it.
}
