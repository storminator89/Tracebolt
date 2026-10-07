//go:build windows

package native

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"reflect"
	"testing"
)

// Only in-memory descriptors/metadata/errors. No file, token or service opens.
func TestAncestorDiagnosticMatchesUnchangedAdmissionDecision(t *testing.T) {
	const base = `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`
	for _, c := range []struct {
		sddl, failure string
		rights        []string
	}{
		{base, "", nil}, {base + `(A;;FRFX;;;BU)`, "", nil}, {base + `(D;;FRFX;;;LS)`, "", nil},
		{`O:BUG:BAD:P(A;;FA;;;SY)`, "owner-untrusted", nil},
		{`O:BAG:BAD:NO_ACCESS_CONTROL`, "dacl-missing", nil},
		{base + `(OA;;FR;11111111-1111-1111-1111-111111111111;;BU)`, "ace-type-unsupported", nil},
		{base + `(A;;0x2;;;BU)`, "untrusted-write-grant", []string{"add-file"}},
		{base + `(A;;0x40;;;BU)`, "untrusted-write-grant", []string{"delete-child"}},
		{base + `(A;;GW;;;BU)`, "untrusted-write-grant", []string{"generic-write"}},
		{base + `(A;IO;GA;;;BU)`, "", nil},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatal("invalid in-memory descriptor")
		}
		failure, rights := ancestorDescriptorDiagnostic(sd)
		if failure != c.failure || !reflect.DeepEqual(rights, c.rights) || ancestorDescriptor(sd) != (c.failure == "") {
			t.Fatal("diagnostic changed trust outcome or category")
		}
	}
	if failure, _ := ancestorDescriptorDiagnostic(nil); failure != "descriptor-invalid" {
		t.Fatal("invalid descriptor not identified")
	}
}
func TestNativeReadFailureClassificationDoesNotPublishNativeError(t *testing.T) {
	for status, want := range map[error]string{windows.STATUS_ACCESS_DENIED: "open-access-denied", windows.STATUS_SHARING_VIOLATION: "open-sharing-violation", windows.STATUS_REPARSE_POINT_ENCOUNTERED: "reparse-point"} {
		if openFailure(fmt.Errorf("private: %w", status)) != want {
			t.Fatal("native status escaped finite diagnostic")
		}
	}
	if openFailure(fmt.Errorf("private: %w", windows.ERROR_ACCESS_DENIED)) != "open-access-denied" || openFailure(windows.ERROR_SHARING_VIOLATION) != "open-sharing-violation" || openFailure(errors.New("private-path")) != "open-failed" {
		t.Fatal("open failure classification invalid")
	}
	for _, c := range []struct {
		err   error
		flags uint32
		want  string
	}{{nil, 0, ""}, {nil, 1, "case-sensitive-directory"}, {windows.STATUS_ACCESS_DENIED, 0, "case-query-denied"}, {windows.STATUS_NOT_SUPPORTED, 0, "case-query-unsupported"}, {windows.STATUS_INVALID_INFO_CLASS, 0, "case-query-unsupported"}, {windows.STATUS_INVALID_PARAMETER, 0, "case-query-invalid"}, {errors.New("private"), 0, "case-query-failed"}} {
		if caseQueryFailure(c.err, c.flags) != c.want {
			t.Fatal("case-query outcome relaxed or exposed")
		}
	}
	for _, c := range []struct {
		info windows.ByHandleFileInformation
		dir  bool
		want string
	}{{windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY}, true, ""}, {windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT}, true, "reparse-point"}, {windows.ByHandleFileInformation{}, true, "object-kind"}, {windows.ByHandleFileInformation{NumberOfLinks: 2}, false, "multiple-links"}, {windows.ByHandleFileInformation{NumberOfLinks: 1}, false, ""}} {
		if fileInformationFailure(c.info, c.dir) != c.want {
			t.Fatal("metadata decision changed")
		}
	}
}
