package native

// PrerequisiteDiagnostic identifies the first failed ancestor check without
// exposing native paths, trustees, descriptors, masks, handles or error strings.
// Rights are canonical finite categories of a rejected allow ACE, never an ACL.
type PrerequisiteDiagnostic struct {
	Location string   `json:"location"`
	Failure  string   `json:"failure"`
	Rights   []string `json:"rights"`
}

var diagnosticRightNames = []string{"generic-all", "generic-write", "change-owner", "change-dacl", "delete-child", "delete", "add-file", "write-ea", "write-attributes"}

func replacementRights(mask uint32) []string {
	bits := []uint32{0x10000000, 0x40000000, 0x80000, 0x40000, 0x40, 0x10000, 0x2, 0x10, 0x100}
	rights := []string{}
	for i, bit := range bits {
		if mask&bit != 0 {
			rights = append(rights, diagnosticRightNames[i])
		}
	}
	return rights
}
func ancestorLocation(index, count int, programFiles bool) string {
	if index == 0 {
		return "volume-root"
	}
	if index == count-1 {
		if programFiles {
			return "program-files"
		}
		return "program-data"
	}
	return "intermediate"
}
func validDiagnosticFailure(v string) bool {
	switch v {
	case "path-syntax", "open-access-denied", "open-sharing-violation", "open-failed",
		"metadata-query-failed", "reparse-point", "object-kind", "multiple-links",
		"final-path-query-failed", "final-path-mismatch", "case-query-denied",
		"case-query-unsupported", "case-query-invalid", "case-query-failed", "case-sensitive-directory",
		"descriptor-query-failed", "descriptor-invalid", "owner-unavailable", "owner-untrusted",
		"dacl-unavailable", "dacl-missing", "ace-malformed", "ace-type-unsupported", "untrusted-write-grant":
		return true
	}
	return false
}
func (d PrerequisiteDiagnostic) valid() bool {
	switch d.Location {
	case "volume-root", "program-files", "program-data", "intermediate":
	default:
		return false
	}
	if !validDiagnosticFailure(d.Failure) || d.Rights == nil {
		return false
	}
	if d.Failure != "untrusted-write-grant" {
		return len(d.Rights) == 0
	}
	if len(d.Rights) == 0 || len(d.Rights) > len(diagnosticRightNames) {
		return false
	}
	cursor := 0
	for _, right := range d.Rights {
		for cursor < len(diagnosticRightNames) && diagnosticRightNames[cursor] != right {
			cursor++
		}
		if cursor == len(diagnosticRightNames) {
			return false
		}
		cursor++
	}
	return true
}
