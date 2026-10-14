package macosservice

// heldInstallIdentity is a platform-neutral model of the descriptor/entry
// metadata comparison used by the Darwin lifecycle lock. Creating the owned
// custody child advances its parent's timestamps and may change its link count,
// but must never change the
// held ancestor identity, owner, mode or ACL-verified descriptor. The final
// installer executable remains exact even in its timestamps and size.
type heldInstallIdentity struct {
	Device           uint64
	Inode            uint64
	UID              uint32
	GID              uint32
	Mode             uint32
	Links            uint64
	Flags            uint64
	Size             int64
	MtimeSeconds     int64
	MtimeNanoseconds int64
	CtimeSeconds     int64
	CtimeNanoseconds int64
}

// strict also compares fields that legitimately advance on an ancestor during
// Claim. Use it for the final executable and for two current views of any node.
func sameHeldInstallIdentity(a, b heldInstallIdentity, strict bool) bool {
	if a.Device != b.Device || a.Inode != b.Inode || a.UID != b.UID || a.GID != b.GID || a.Mode != b.Mode || a.Flags != b.Flags || b.Links == 0 {
		return false
	}
	if strict && (a.Links != b.Links || a.Size != b.Size || a.MtimeSeconds != b.MtimeSeconds || a.MtimeNanoseconds != b.MtimeNanoseconds || a.CtimeSeconds != b.CtimeSeconds || a.CtimeNanoseconds != b.CtimeNanoseconds) {
		return false
	}
	return true
}

// A running sender may advance only selected private directory metadata. Even
// there, two current views of the same node must match exactly. The native
// caller separately performs an ACL-checked Fstat before this comparison.
func samePhaseDirectoryNode(original, current, entry heldInstallIdentity, mutablePrivate bool) bool {
	return sameHeldInstallIdentity(original, current, !mutablePrivate) && sameHeldInstallIdentity(current, entry, true)
}
