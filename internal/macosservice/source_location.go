package macosservice

// fileIdentity represents a descriptor-held filesystem object. Source archive
// selection must stay outside the fixed installation directory even when a
// case-insensitive or otherwise aliased path bypasses textual path comparison.
type fileIdentity struct {
	device uint64
	inode  uint64
}

func sourceOutsideInstall(install fileIdentity, sourceAncestors []fileIdentity) bool {
	if install.inode == 0 || len(sourceAncestors) == 0 {
		return false
	}
	for _, ancestor := range sourceAncestors {
		if ancestor.inode == 0 || ancestor == install {
			return false
		}
	}
	return true
}
